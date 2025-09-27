#!/usr/bin/env python3
"""
Advanced Taint Tracking System for PHP HNP Analysis

This is the main taint tracking system that integrates:
1. PHP AST parsing
2. Data flow analysis
3. Taint propagation
4. Inter-procedural analysis
5. Control flow analysis
"""

import os
import sys
import json
import time
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

from php_ast_parser import PHPASTParser, ASTNode, AssignmentNode, FunctionCallNode, VariableNode
from dataflow_analyzer import DataFlowAnalyzer, DataFlowEdge, VariableState


class TaintSource:
    """Represents a taint source"""
    def __init__(self, file: str, line: int, column: int, variable: str, source_type: str, context: str, confidence: float = 1.0):
        self.file = file
        self.line = line
        self.column = column
        self.variable = variable
        self.source_type = source_type
        self.context = context
        self.confidence = confidence


class TaintSink:
    """Represents a taint sink"""
    def __init__(self, file: str, line: int, column: int, function: str, arguments: List[str],
                 sink_type: str, context: str, tainted_arguments: List[int] = None):
        self.file = file
        self.line = line
        self.column = column
        self.function = function
        self.arguments = arguments
        self.sink_type = sink_type
        self.context = context
        self.tainted_arguments = tainted_arguments or []


class TaintFlow:
    """Represents a complete taint flow"""
    def __init__(self, source: TaintSource, sink: TaintSink, flow_path: List[Tuple[str, int, str]],
                 tainted_variables: Set[str], has_guard: bool, has_validation: bool,
                 confidence: float, flow_type: str):
        self.source = source
        self.sink = sink
        self.flow_path = flow_path
        self.tainted_variables = tainted_variables
        self.has_guard = has_guard
        self.has_validation = has_validation
        self.confidence = confidence
        self.flow_type = flow_type


class AdvancedTaintTracker:
    """Advanced taint tracking system"""
    
    def __init__(self):
        self.parser = PHPASTParser()
        self.dataflow_analyzer = DataFlowAnalyzer()
        
        # Results
        self.sources: List[TaintSource] = []
        self.sinks: List[TaintSink] = []
        self.flows: List[TaintFlow] = []
        self.variable_states: Dict[str, VariableState] = {}
        
        # Configuration
        self.min_confidence = 0.3
        self.enable_inter_procedural = True
        self.enable_control_flow = True
    
    def analyze_framework(self, framework_root: str, framework_name: str) -> Dict[str, Any]:
        """Analyze a framework for HNP vulnerabilities using advanced taint tracking"""
        print(f"🔍 Starting advanced taint tracking analysis for {framework_name}...")
        start_time = time.time()
        
        # Step 1: Find and parse all PHP files
        php_files = self._find_php_files(framework_root)
        print(f"📁 Found {len(php_files)} PHP files")
        
        # Step 2: Parse files into AST
        parsed_files = self._parse_files(php_files)
        print(f"📄 Parsed {len(parsed_files)} files successfully")
        
        # Step 3: Detect taint sources and sinks
        self._detect_sources_and_sinks(parsed_files)
        print(f"🎯 Found {len(self.sources)} sources and {len(self.sinks)} sinks")
        
        # Step 4: Perform data flow analysis
        dataflow_result = self.dataflow_analyzer.analyze_dataflow(parsed_files)
        print(f"🔄 Data flow analysis: {dataflow_result['total_flows']} flows")
        
        # Step 5: Track taint propagation
        self._track_taint_propagation(parsed_files, dataflow_result)
        print(f"🚨 Found {len(self.flows)} taint flows")
        
        # Step 6: Analyze control flow (if enabled)
        if self.enable_control_flow:
            self._analyze_control_flow(parsed_files)
        
        # Step 7: Generate results
        results = self._generate_results(framework_name, time.time() - start_time)
        
        return results
    
    def _find_php_files(self, framework_root: str) -> List[str]:
        """Find all PHP files in the framework"""
        php_files = []
        
        for root, dirs, files in os.walk(framework_root):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in [
                ".git", "vendor", "node_modules", "tests", "test", "spec", 
                "docs", "documentation", "cache", "tmp", "temp"
            ]]
            
            for file in files:
                if file.endswith(('.php', '.blade.php', '.phtml')):
                    php_files.append(os.path.join(root, file))
        
        return php_files
    
    def _parse_files(self, php_files: List[str]) -> List[Dict[str, Any]]:
        """Parse all PHP files into AST"""
        parsed_files = []
        
        for i, file_path in enumerate(php_files):
            if i % 100 == 0:
                print(f"📄 Parsing: {i}/{len(php_files)}")
            
            try:
                parsed = self.parser.parse_file(file_path)
                if parsed:
                    parsed_files.append(parsed)
            except Exception as e:
                print(f"⚠️  Error parsing {file_path}: {e}")
                continue
        
        return parsed_files
    
    def _detect_sources_and_sinks(self, parsed_files: List[Dict[str, Any]]):
        """Detect taint sources and sinks in parsed files"""
        for file_data in parsed_files:
            file_path = file_data['file']
            
            # Detect sources
            for source_node in file_data['taint_sources']:
                source = self._create_taint_source(source_node, file_path)
                if source:
                    self.sources.append(source)
            
            # Detect sinks
            for sink_node in file_data['taint_sinks']:
                sink = self._create_taint_sink(sink_node, file_path)
                if sink:
                    self.sinks.append(sink)
    
    def _create_taint_source(self, source_node: ASTNode, file_path: str) -> Optional[TaintSource]:
        """Create a TaintSource from an AST node"""
        if isinstance(source_node, AssignmentNode):
            # Extract source type from the right-hand expression
            source_type = self._infer_source_type(source_node.right_expr)
            if source_type:
                return TaintSource(
                    file=file_path,
                    line=source_node.line,
                    column=source_node.column,
                    variable=source_node.left_var,
                    source_type=source_type,
                    context=source_node.content,
                    confidence=1.0
                )
        elif isinstance(source_node, VariableNode):
            source_type = self._infer_source_type(source_node)
            if source_type:
                return TaintSource(
                    file=file_path,
                    line=source_node.line,
                    column=source_node.column,
                    variable=source_node.name,
                    source_type=source_type,
                    context=source_node.content,
                    confidence=1.0
                )
        
        return None
    
    def _create_taint_sink(self, sink_node: ASTNode, file_path: str) -> Optional[TaintSink]:
        """Create a TaintSink from an AST node"""
        if isinstance(sink_node, FunctionCallNode):
            sink_type = self._infer_sink_type(sink_node.function_name)
            if sink_type:
                # Extract arguments
                args = []
                for arg in sink_node.arguments:
                    if isinstance(arg, VariableNode):
                        args.append(arg.name)
                    else:
                        args.append(str(arg.content))
                
                return TaintSink(
                    file=file_path,
                    line=sink_node.line,
                    column=sink_node.column,
                    function=sink_node.function_name,
                    arguments=args,
                    sink_type=sink_type,
                    context=sink_node.content
                )
        
        return None
    
    def _infer_source_type(self, expr: ASTNode) -> Optional[str]:
        """Infer the type of taint source from an expression"""
        content = expr.content if hasattr(expr, 'content') else str(expr)
        
        if '$_SERVER' in content and 'HTTP_HOST' in content:
            return 'http_host'
        elif '$_SERVER' in content and 'SERVER_NAME' in content:
            return 'server_name'
        elif 'getHost' in content:
            return 'request_method'
        elif 'X-Forwarded-Host' in content:
            return 'proxy_header'
        
        return None
    
    def _infer_sink_type(self, func_name: str) -> Optional[str]:
        """Infer the type of taint sink from function name"""
        url_generation = ['url', 'route', 'generateUrl', 'createUrl', 'home_url', 'site_url', 'admin_url', 'esc_url']
        redirect = ['redirect', 'wp_safe_redirect', 'RedirectResponse']
        authentication = ['wp_login_url', 'wp_logout_url', 'login', 'logout']
        
        if func_name in url_generation:
            return 'url_generation'
        elif func_name in redirect:
            return 'redirect'
        elif func_name in authentication:
            return 'authentication'
        
        return None
    
    def _track_taint_propagation(self, parsed_files: List[Dict[str, Any]], dataflow_result: Dict[str, Any]):
        """Track taint propagation from sources to sinks"""
        # Get data flow edges
        dataflow_edges = dataflow_result.get('flows', [])
        
        # Create a mapping of variables to their taint status
        tainted_variables = set()
        
        # Mark source variables as tainted
        for source in self.sources:
            tainted_variables.add(source.variable)
        
        # Propagate taint through data flow edges
        for edge_data in dataflow_edges:
            source_var = edge_data['source_var']
            target_var = edge_data['target_var']
            confidence = edge_data['confidence']
            
            if source_var in tainted_variables and confidence > self.min_confidence:
                tainted_variables.add(target_var)
        
        # Find flows from tainted variables to sinks
        for sink in self.sinks:
            for i, arg in enumerate(sink.arguments):
                if arg in tainted_variables:
                    # Find the source that tainted this argument
                    source = self._find_taint_source_for_variable(arg)
                    if source:
                        flow = self._create_taint_flow(source, sink, arg, i)
                        if flow:
                            self.flows.append(flow)
    
    def _find_taint_source_for_variable(self, variable: str) -> Optional[TaintSource]:
        """Find the taint source for a given variable"""
        for source in self.sources:
            if source.variable == variable:
                return source
        return None
    
    def _create_taint_flow(self, source: TaintSource, sink: TaintSink, 
                          tainted_var: str, arg_index: int) -> Optional[TaintFlow]:
        """Create a taint flow from source to sink"""
        # Build flow path
        flow_path = [
            (source.file, source.line, f"source: {source.variable}"),
            (sink.file, sink.line, f"sink: {sink.function}({tainted_var})")
        ]
        
        # Check for guards and validation
        has_guard = self._check_guards(source, sink)
        has_validation = self._check_validation(source, sink)
        
        # Calculate confidence
        confidence = self._calculate_flow_confidence(source, sink, has_guard, has_validation)
        
        if confidence < self.min_confidence:
            return None
        
        # Determine flow type
        flow_type = 'direct' if source.file == sink.file else 'indirect'
        
        return TaintFlow(
            source=source,
            sink=sink,
            flow_path=flow_path,
            tainted_variables={tainted_var},
            has_guard=has_guard,
            has_validation=has_validation,
            confidence=confidence,
            flow_type=flow_type
        )
    
    def _check_guards(self, source: TaintSource, sink: TaintSink) -> bool:
        """Check if the flow is protected by guards"""
        # Look for sanitization functions between source and sink
        guard_patterns = [
            r'filter_var\s*\(',
            r'htmlspecialchars\s*\(',
            r'strip_tags\s*\(',
            r'preg_replace\s*\(',
            r'sanitize\s*\(',
        ]
        
        # Check source and sink files for guards
        for file_path in [source.file, sink.file]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern in guard_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
            except:
                continue
        
        return False
    
    def _check_validation(self, source: TaintSource, sink: TaintSink) -> bool:
        """Check if the flow has validation"""
        validation_patterns = [
            r'isset\s*\(',
            r'empty\s*\(',
            r'is_string\s*\(',
            r'preg_match\s*\(',
            r'validate\s*\(',
        ]
        
        for file_path in [source.file, sink.file]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern in validation_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
            except:
                continue
        
        return False
    
    def _calculate_flow_confidence(self, source: TaintSource, sink: TaintSink, 
                                 has_guard: bool, has_validation: bool) -> float:
        """Calculate confidence in this taint flow"""
        confidence = 0.8  # Base confidence
        
        # Adjust based on source and sink types
        if source.source_type == 'http_host' and sink.sink_type == 'url_generation':
            confidence += 0.2
        
        # Reduce confidence if protected
        if has_guard:
            confidence -= 0.3
        if has_validation:
            confidence -= 0.2
        
        # Reduce confidence for cross-file flows
        if source.file != sink.file:
            confidence -= 0.1
        
        return max(0.0, min(1.0, confidence))
    
    def _analyze_control_flow(self, parsed_files: List[Dict[str, Any]]):
        """Analyze control flow for additional taint flows"""
        # This is a placeholder for control flow analysis
        # In a full implementation, we would:
        # 1. Build control flow graphs
        # 2. Analyze conditional branches
        # 3. Handle loops and iterations
        # 4. Track taint through control flow
        pass
    
    def _generate_results(self, framework_name: str, analysis_time: float) -> Dict[str, Any]:
        """Generate final analysis results"""
        # Categorize flows by confidence
        high_confidence_flows = [f for f in self.flows if f.confidence > 0.7]
        medium_confidence_flows = [f for f in self.flows if 0.4 <= f.confidence <= 0.7]
        low_confidence_flows = [f for f in self.flows if f.confidence < 0.4]
        
        # Categorize by sink type
        sink_type_counts = defaultdict(int)
        for flow in self.flows:
            sink_type_counts[flow.sink.sink_type] += 1
        
        return {
            'framework': framework_name,
            'analysis_time': analysis_time,
            'total_sources': len(self.sources),
            'total_sinks': len(self.sinks),
            'total_flows': len(self.flows),
            'high_confidence_flows': len(high_confidence_flows),
            'medium_confidence_flows': len(medium_confidence_flows),
            'low_confidence_flows': len(low_confidence_flows),
            'sink_type_breakdown': dict(sink_type_counts),
            'flows': [
                {
                    'source': {
                        'file': flow.source.file,
                        'line': flow.source.line,
                        'column': flow.source.column,
                        'variable': flow.source.variable,
                        'source_type': flow.source.source_type,
                        'context': flow.source.context,
                        'confidence': flow.source.confidence
                    },
                    'sink': {
                        'file': flow.sink.file,
                        'line': flow.sink.line,
                        'column': flow.sink.column,
                        'function': flow.sink.function,
                        'arguments': flow.sink.arguments,
                        'sink_type': flow.sink.sink_type,
                        'context': flow.sink.context,
                        'tainted_arguments': flow.sink.tainted_arguments
                    },
                    'confidence': flow.confidence,
                    'has_guard': flow.has_guard,
                    'has_validation': flow.has_validation,
                    'flow_type': flow.flow_type,
                    'flow_path': flow.flow_path
                }
                for flow in self.flows
            ]
        }


def main():
    """Main function for testing"""
    if len(sys.argv) != 3:
        print("Usage: python3 advanced_taint_tracker.py <framework_root> <framework_name>")
        sys.exit(1)
    
    framework_root = sys.argv[1]
    framework_name = sys.argv[2]
    
    tracker = AdvancedTaintTracker()
    results = tracker.analyze_framework(framework_root, framework_name)
    
    # Save results
    output_file = f"/home/rui/HNP_PHP/reports/framework_analysis/{framework_name}/{framework_name}_advanced_taint_flows.json"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"💾 Results saved to: {output_file}")
    print(f"📊 Summary:")
    print(f"  - Sources: {results['total_sources']}")
    print(f"  - Sinks: {results['total_sinks']}")
    print(f"  - Total flows: {results['total_flows']}")
    print(f"  - High confidence: {results['high_confidence_flows']}")
    print(f"  - Medium confidence: {results['medium_confidence_flows']}")
    print(f"  - Low confidence: {results['low_confidence_flows']}")


if __name__ == "__main__":
    main()
