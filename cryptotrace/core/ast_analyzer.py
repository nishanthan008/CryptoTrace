
import esprima
import logging

class ASTAnalyzer:
    """
    Advanced SAST engine for JavaScript cryptographic analysis.
    Uses sink-driven detection, data-flow tracing, and algorithmic context.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Cryptographic Sinks: Function calls that trigger analysis
        self.sinks = {
            'window.crypto.subtle.encrypt': {'key_idx': 1, 'algo_idx': 0, 'type': 'Encryption'},
            'window.crypto.subtle.decrypt': {'key_idx': 1, 'algo_idx': 0, 'type': 'Decryption'},
            'window.crypto.subtle.importKey': {'key_idx': 1, 'type': 'Key Import'},
            'window.crypto.subtle.deriveKey': {'key_idx': 1, 'type': 'Key Derivation'},
            'crypto.subtle.encrypt': {'key_idx': 1, 'algo_idx': 0, 'type': 'Encryption'},
            'crypto.subtle.decrypt': {'key_idx': 1, 'algo_idx': 0, 'type': 'Decryption'},
            'CryptoJS.AES.encrypt': {'key_idx': 1, 'algo_idx': 2, 'type': 'AES Encryption'},
            'CryptoJS.AES.decrypt': {'key_idx': 1, 'algo_idx': 2, 'type': 'AES Decryption'},
            'CryptoJS.DES.encrypt': {'key_idx': 1, 'algo_idx': 2, 'type': 'DES Encryption (Weak)'},
        }
        self.scope = {}

    def analyze(self, js_content, url="unknown"):
        """
        Main entry point for AST-based analysis.
        """
        findings = []
        try:
            # Parse tolerant of module/script differences
            try:
                tree = esprima.parseScript(js_content, {'tolerant': True, 'loc': True})
            except:
                tree = esprima.parseModule(js_content, {'tolerant': True, 'loc': True})
            
            # Phase 1: Global Scope Collection (Identify variable declarations and assignments)
            self.scope = self._collect_scope(tree)
            
            # Phase 2: Sink-Driven Analysis (Find crypto calls and trace their arguments)
            findings = self._analyze_sinks(tree, js_content)
        except Exception as e:
            self.logger.debug(f"Advanced AST Analysis failed for {url}: {e}")
        
        return findings

    def _collect_scope(self, node, scope=None):
        if scope is None: scope = {}
        
        if not hasattr(node, 'type'): return scope

        # Variable Declarations: var x = ...
        if node.type == 'VariableDeclarator':
            if node.id.type == 'Identifier' and node.init:
                scope[node.id.name] = node.init
        
        # Assignments: x = ...
        elif node.type == 'AssignmentExpression':
            if node.left.type == 'Identifier' and node.operator == '=':
                scope[node.left.name] = node.right

        # Recursively walk to build global dictionary (simplified view of scope)
        for key, value in node.__dict__.items():
            if key in ['loc', 'range']: continue
            if isinstance(value, list):
                for item in value: self._collect_scope(item, scope)
            elif hasattr(value, 'type'):
                self._collect_scope(value, scope)
        
        return scope

    def _analyze_sinks(self, node, source):
        findings = []
        if not hasattr(node, 'type'): return findings

        if node.type == 'CallExpression':
            callee_name = self._get_full_name(node.callee)
            sink_info = self._match_sink(callee_name)
            
            if sink_info:
                findings.extend(self._process_sink(node, sink_info, source))

        for key, value in node.__dict__.items():
            if key in ['loc', 'range']: continue
            if isinstance(value, list):
                for item in value: findings.extend(self._analyze_sinks(item, source))
            elif hasattr(value, 'type'):
                findings.extend(self._analyze_sinks(value, source))
        
        return findings

    def _process_sink(self, call_node, sink_info, source):
        findings = []
        args = call_node.arguments
        
        # 1. Key Tracing (Taint Analysis)
        key_idx = sink_info.get('key_idx')
        if key_idx is not None and key_idx < len(args):
            key_node = args[key_idx]
            trace = self._trace_variable(key_node)
            if trace['is_literal']:
                 findings.append({
                    "category": "hardcoded_crypto_material",
                    "severity": "CRITICAL",
                    "description": f"Hardcoded Key traced through data-flow to {sink_info['type']}",
                    "evidence": f"Trace: {trace['path']} -> '{trace['value']}'",
                    "cwe": "CWE-321",
                    "confidence": 9,
                    "line": call_node.loc.start.line
                })

        # 2. Algorithm & IV Analysis
        algo_idx = sink_info.get('algo_idx')
        if algo_idx is not None and algo_idx < len(args):
            algo_node = args[algo_idx]
            algo_details = self._resolve_object(algo_node)
            
            # Check for Static/Hardcoded IV
            iv_node = algo_details.get('iv') or algo_details.get('counter') or algo_details.get('nonce')
            if iv_node:
                iv_trace = self._trace_variable(iv_node)
                if iv_trace['is_literal']:
                     findings.append({
                        "category": "static_iv_detection",
                        "severity": "HIGH",
                        "description": f"Static/Hardcoded IV detected in {sink_info['type']}",
                        "evidence": f"IV trace: {iv_trace['path']} -> '{iv_trace['value']}'",
                        "cwe": "CWE-329",
                        "confidence": 8,
                        "line": call_node.loc.start.line
                    })

            # Check for Weak Modes (e.g., ECB)
            mode = algo_details.get('mode')
            if mode:
                mode_trace = self._trace_variable(mode)
                if 'ECB' in str(mode_trace['value']).upper():
                     findings.append({
                        "category": "weak_cryptographic_mode",
                        "severity": "HIGH",
                        "description": "Insecure ECB mode detected in cryptographic operation",
                        "evidence": f"Mode parameter traced to ECB",
                        "cwe": "CWE-327",
                        "confidence": 10,
                        "line": call_node.loc.start.line
                    })

        # 3. Verified Usage (Context)
        findings.append({
            "category": "verified_crypto_usage",
            "severity": "INFO",
            "description": f"Verified Cryptographic Operation: {sink_info['type']}",
            "evidence": f"Validated sink call: {self._get_full_name(call_node.callee)}",
            "confidence": 10,
            "line": call_node.loc.start.line
        })

        return findings

    def _trace_variable(self, node, path=None, visited=None):
        if path is None: path = []
        if visited is None: visited = set()
        
        res = {'is_literal': False, 'value': None, 'path': " -> ".join(path)}

        if node.type == 'Literal':
            res['is_literal'] = True
            res['value'] = node.value
            res['path'] = " -> ".join(path + [f"Literal({node.value})"])
            return res
        
        if node.type == 'Identifier':
            name = node.name
            path.append(f"Var({name})")
            if name in visited: return res # Cycle detection
            visited.add(name)
            
            if name in self.scope:
                return self._trace_variable(self.scope[name], path, visited)
            else:
                res['path'] = " -> ".join(path + ["Dynamic/Unknown Source"])
                res['value'] = name # Fallback to name
                return res
        
        if node.type == 'MemberExpression':
            name = self._get_full_name(node)
            res['value'] = name
            res['path'] = " -> ".join(path + [f"Member({name})"])
            return res

        return res

    def _resolve_object(self, node):
        """Attempts to resolve properties of an object (ObjectExpression or Identifier)"""
        properties = {}
        if node.type == 'ObjectExpression':
            for prop in node.properties:
                if hasattr(prop.key, 'name'):
                    properties[prop.key.name] = prop.value
                elif hasattr(prop.key, 'value'): # String key
                    properties[str(prop.key.value)] = prop.value
        elif node.type == 'Identifier':
            if node.name in self.scope:
                # Recursively resolve if it's an Identifier pointing to an Object
                return self._resolve_object(self.scope[node.name])
        return properties

    def _get_full_name(self, node):
        if node.type == 'MemberExpression':
            obj = self._get_full_name(node.object)
            prop = node.property.name if hasattr(node.property, 'name') else '?'
            return f"{obj}.{prop}"
        elif node.type == 'Identifier':
            return node.name
        return "unknown"

    def _match_sink(self, name):
        if name in self.sinks: return self.sinks[name]
        for sink, info in self.sinks.items():
            if name.endswith(sink) or sink.endswith(name): return info
        return None

