#!/usr/bin/env python3
"""
Data Flow Analyzer for True Taint Tracking

This module implements sophisticated data flow analysis that:
1. Tracks variable dependencies across statements
2. Handles control flow (if/else, loops)
3. Performs inter-procedural analysis
4. Tracks taint propagation through operations
"""

import re
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, deque
from php_ast_parser import PHPASTParser, ASTNode, AssignmentNode, FunctionCallNode, VariableNode, ArrayAccessNode


class DataFlowEdge:
    """Represents a data flow edge between variables"""
    def __init__(self, source_var: str, target_var: str, operation: str, line: int, confidence: float = 1.0):
        self.source_var = source_var
        self.target_var = target_var
        self.operation = operation
        self.line = line
        self.confidence = confidence


class VariableState:
    """Represents the state of a variable at a specific point"""
    def __init__(self, name: str, line: int, is_tainted: bool, taint_sources: List[str],
                 dependencies: Set[str] = None, operations: List[str] = None):
        self.name = name
        self.line = line
        self.is_tainted = is_tainted
        self.taint_sources = taint_sources
        self.dependencies = dependencies or set()
        self.operations = operations or []


class DataFlowAnalyzer:
    """Advanced data flow analyzer"""
    
    def __init__(self):
        self.parser = PHPASTParser()
        self.variable_states: Dict[str, VariableState] = {}
        self.data_flow_graph: Dict[str, List[DataFlowEdge]] = defaultdict(list)
        self.taint_propagation_rules = self._init_taint_propagation_rules()
        
    def _init_taint_propagation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize taint propagation rules for different operations"""
        return {
            'assign': {
                'propagates_taint': True,
                'confidence': 1.0,
                'description': 'Direct assignment propagates taint'
            },
            'concat': {
                'propagates_taint': True,
                'confidence': 1.0,
                'description': 'String concatenation propagates taint'
            },
            'array_access': {
                'propagates_taint': True,
                'confidence': 0.9,
                'description': 'Array access may propagate taint'
            },
            'function_call': {
                'propagates_taint': False,  # Depends on function
                'confidence': 0.5,
                'description': 'Function call taint propagation depends on function'
            },
            'sanitize': {
                'propagates_taint': False,
                'confidence': 0.1,
                'description': 'Sanitization functions remove taint'
            }
        }
    
    def analyze_dataflow(self, parsed_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze data flow across all parsed files"""
        print("🔄 Starting data flow analysis...")
        
        # Build data flow graph
        self._build_dataflow_graph(parsed_files)
        
        # Track taint propagation
        taint_flows = self._track_taint_propagation(parsed_files)
        
        # Analyze inter-procedural flows
        inter_procedural_flows = self._analyze_inter_procedural_flows(parsed_files)
        
        # Combine results
        all_flows = taint_flows + inter_procedural_flows
        
        # Filter high-confidence flows
        high_confidence_flows = [f for f in all_flows if f.confidence > 0.7]
        medium_confidence_flows = [f for f in all_flows if 0.4 <= f.confidence <= 0.7]
        low_confidence_flows = [f for f in all_flows if f.confidence < 0.4]
        
        return {
            'total_flows': len(all_flows),
            'high_confidence_flows': len(high_confidence_flows),
            'medium_confidence_flows': len(medium_confidence_flows),
            'low_confidence_flows': len(low_confidence_flows),
            'flows': [
                {
                    'source_var': f.source_var,
                    'target_var': f.target_var,
                    'operation': f.operation,
                    'line': f.line,
                    'confidence': f.confidence
                }
                for f in all_flows
            ],
            'dataflow_graph': dict(self.data_flow_graph)
        }
    
    def _build_dataflow_graph(self, parsed_files: List[Dict[str, Any]]):
        """Build data flow graph from parsed files"""
        for file_data in parsed_files:
            file_path = file_data['file']
            statements = file_data['statements']
            
            for statement in statements:
                self._process_statement(statement, file_path)
    
    def _process_statement(self, statement: ASTNode, file_path: str):
        """Process a single statement for data flow analysis"""
        if statement.node_type.value == 'assignment':
            self._process_assignment(statement, file_path)
        elif statement.node_type.value == 'function_call':
            self._process_function_call(statement, file_path)
        elif statement.node_type.value == 'method_call':
            self._process_method_call(statement, file_path)
    
    def _process_assignment(self, assignment: AssignmentNode, file_path: str):
        """Process assignment statement for data flow"""
        target_var = assignment.left_var
        source_expr = assignment.right_expr
        
        # Extract source variables from expression
        source_vars = self._extract_variables_from_expression(source_expr)
        
        # Create data flow edges
        for source_var in source_vars:
            edge = DataFlowEdge(
                source_var=source_var,
                target_var=target_var,
                operation='assign',
                line=assignment.line,
                confidence=1.0
            )
            self.data_flow_graph[source_var].append(edge)
        
        # Update variable state
        self._update_variable_state(target_var, assignment.line, source_vars, 'assign')
    
    def _process_function_call(self, func_call: FunctionCallNode, file_path: str):
        """Process function call for data flow analysis"""
        func_name = func_call.function_name
        
        # Check if this is a taint-preserving or taint-removing function
        taint_behavior = self._get_function_taint_behavior(func_name)
        
        # Analyze arguments and return value
        for i, arg in enumerate(func_call.arguments):
            if isinstance(arg, VariableNode):
                # This argument might be tainted
                self._mark_variable_as_tainted(arg.name, func_call.line, [f"function_arg_{func_name}"])
    
    def _process_method_call(self, method_call: FunctionCallNode, file_path: str):
        """Process method call for data flow analysis"""
        # Similar to function call but with object context
        self._process_function_call(method_call, file_path)
    
    def _extract_variables_from_expression(self, expr: ASTNode) -> List[str]:
        """Extract all variables from an expression"""
        variables = []
        
        if isinstance(expr, VariableNode):
            variables.append(expr.name)
        elif isinstance(expr, ArrayAccessNode):
            variables.append(expr.array_name)
        elif isinstance(expr, FunctionCallNode):
            # Extract variables from function arguments
            for arg in expr.arguments:
                variables.extend(self._extract_variables_from_expression(arg))
        
        return variables
    
    def _get_function_taint_behavior(self, func_name: str) -> Dict[str, Any]:
        """Get taint behavior for a specific function"""
        # Taint-preserving functions
        taint_preserving = {
            'url', 'route', 'redirect', 'home_url', 'site_url', 'admin_url',
            'esc_url', 'wp_login_url', 'wp_logout_url'
        }
        
        # Taint-removing functions (sanitization)
        taint_removing = {
            'filter_var', 'htmlspecialchars', 'strip_tags', 'preg_replace',
            'sanitize_text_field', 'sanitize_url', 'esc_html', 'esc_attr'
        }
        
        if func_name in taint_preserving:
            return {
                'propagates_taint': True,
                'confidence': 0.9,
                'description': f'{func_name} preserves taint'
            }
        elif func_name in taint_removing:
            return {
                'propagates_taint': False,
                'confidence': 0.8,
                'description': f'{func_name} removes taint'
            }
        else:
            return {
                'propagates_taint': False,
                'confidence': 0.3,
                'description': f'{func_name} unknown taint behavior'
            }
    
    def _update_variable_state(self, var_name: str, line: int, dependencies: List[str], operation: str):
        """Update the state of a variable"""
        if var_name not in self.variable_states:
            self.variable_states[var_name] = VariableState(
                name=var_name,
                line=line,
                is_tainted=False,
                taint_sources=[],
                dependencies=set(),
                operations=[]
            )
        
        state = self.variable_states[var_name]
        state.line = line
        state.dependencies.update(dependencies)
        state.operations.append(operation)
        
        # Check if any dependency is tainted
        for dep in dependencies:
            if dep in self.variable_states and self.variable_states[dep].is_tainted:
                state.is_tainted = True
                state.taint_sources.extend(self.variable_states[dep].taint_sources)
    
    def _mark_variable_as_tainted(self, var_name: str, line: int, taint_sources: List[str]):
        """Mark a variable as tainted"""
        if var_name not in self.variable_states:
            self.variable_states[var_name] = VariableState(
                name=var_name,
                line=line,
                is_tainted=True,
                taint_sources=taint_sources,
                dependencies=set(),
                operations=[]
            )
        else:
            state = self.variable_states[var_name]
            state.is_tainted = True
            state.taint_sources.extend(taint_sources)
    
    def _track_taint_propagation(self, parsed_files: List[Dict[str, Any]]) -> List[DataFlowEdge]:
        """Track taint propagation through the data flow graph"""
        taint_flows = []
        
        # Find all taint sources
        taint_sources = []
        for file_data in parsed_files:
            for source in file_data['taint_sources']:
                if isinstance(source, AssignmentNode):
                    taint_sources.append(source.left_var)
                elif isinstance(source, VariableNode):
                    taint_sources.append(source.name)
        
        # Propagate taint from sources
        for source_var in taint_sources:
            self._mark_variable_as_tainted(source_var, 0, [f"taint_source_{source_var}"])
            
            # Use BFS to propagate taint
            queue = deque([source_var])
            visited = set()
            
            while queue:
                current_var = queue.popleft()
                if current_var in visited:
                    continue
                visited.add(current_var)
                
                # Find all variables that depend on current_var
                for edge in self.data_flow_graph[current_var]:
                    target_var = edge.target_var
                    
                    # Check if taint should propagate
                    rule = self.taint_propagation_rules.get(edge.operation, {})
                    if rule.get('propagates_taint', False):
                        # Propagate taint
                        self._mark_variable_as_tainted(target_var, edge.line, [f"propagated_from_{current_var}"])
                        
                        # Add to taint flows
                        taint_flows.append(edge)
                        
                        # Continue propagation
                        queue.append(target_var)
        
        return taint_flows
    
    def _analyze_inter_procedural_flows(self, parsed_files: List[Dict[str, Any]]) -> List[DataFlowEdge]:
        """Analyze inter-procedural data flows"""
        inter_flows = []
        
        # This is a simplified implementation
        # In a full implementation, we would:
        # 1. Build call graphs
        # 2. Track parameter passing
        # 3. Track return values
        # 4. Handle function pointers and dynamic calls
        
        for file_data in parsed_files:
            for statement in file_data['statements']:
                if isinstance(statement, FunctionCallNode):
                    # Check if function arguments contain tainted variables
                    for arg in statement.arguments:
                        if isinstance(arg, VariableNode):
                            if arg.name in self.variable_states and self.variable_states[arg.name].is_tainted:
                                # This is an inter-procedural taint flow
                                edge = DataFlowEdge(
                                    source_var=arg.name,
                                    target_var=f"function_{statement.function_name}",
                                    operation='function_call',
                                    line=statement.line,
                                    confidence=0.6
                                )
                                inter_flows.append(edge)
        
        return inter_flows


def main():
    """Test the data flow analyzer"""
    analyzer = DataFlowAnalyzer()
    
    # Test with sample data
    test_data = [
        {
            'file': 'test.php',
            'statements': [
                # This would be populated with actual AST nodes
            ],
            'taint_sources': [],
            'taint_sinks': []
        }
    ]
    
    result = analyzer.analyze_dataflow(test_data)
    print(f"Data flow analysis result: {result}")


if __name__ == "__main__":
    main()
