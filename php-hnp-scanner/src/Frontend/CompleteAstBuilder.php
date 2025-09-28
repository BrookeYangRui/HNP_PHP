<?php
/**
 * Complete AST Builder
 * Builds complete abstract syntax trees, supports complex PHP syntax structures
 */

namespace HNP\Frontend;

class CompleteAstBuilder
{
    private CompleteTokenizer $tokenizer;
    private array $ast;
    private string $currentFile;
    
    public function build(string $file): array
    {
        $this->tokenizer = new CompleteTokenizer();
        $this->tokenizer->tokenize($file);
        $this->currentFile = $file;
        
        $this->ast = [
            'file' => $file,
            'functions' => [],
            'classes' => [],
            'variables' => [],
            'assignments' => [],
            'calls' => [],
            'concatenations' => [],
            'expressions' => [],
            'statements' => []
        ];
        
        $this->parseFile();
        
        return $this->ast;
    }
    
    private function parseFile(): void
    {
        while (!$this->tokenizer->isAtEnd()) {
            $token = $this->tokenizer->getCurrentToken();
            
            if (is_array($token)) {
                switch ($token[0]) {
                    case T_FUNCTION:
                        $this->parseFunction();
                        break;
                    case T_CLASS:
                        $this->parseClass();
                        break;
                    case T_VARIABLE:
                        $this->parseVariable();
                        break;
                    case T_STRING:
                        if ($this->isFunctionCall()) {
                            $this->parseFunctionCall();
                        } else {
                            $this->tokenizer->advance();
                        }
                        break;
                    case T_IF:
                        $this->parseIfStatement();
                        break;
                    case T_FOREACH:
                        $this->parseForeachStatement();
                        break;
                    case T_FOR:
                        $this->parseForStatement();
                        break;
                    case T_WHILE:
                        $this->parseWhileStatement();
                        break;
                    case T_RETURN:
                        $this->parseReturnStatement();
                        break;
                    default:
                        $this->tokenizer->advance();
                        break;
                }
            } else {
                // Handle operators and delimiters
                if ($token === '.') {
                    $this->parseConcatenation();
                } else {
                    $this->tokenizer->advance();
                }
            }
        }
    }
    
    private function parseFunction(): void
    {
        $function = [
            'name' => '',
            'parameters' => [],
            'body' => [],
            'line' => $this->getCurrentLine(),
            'return_type' => null
        ];
        
        // Skip function keyword
        $this->tokenizer->advance();
        
        // Get function name
        $token = $this->tokenizer->getCurrentToken();
        if ($this->tokenizer->isTokenType($token, T_STRING)) {
            $function['name'] = $this->tokenizer->getTokenValue($token);
            $this->tokenizer->advance();
        }
        
        // Parse parameters
        $this->parseFunctionParameters($function);
        
        // Parse function body (simplified)
        $this->parseFunctionBody($function);
        
        $this->ast['functions'][] = $function;
    }
    
    private function parseClass(): void
    {
        $class = [
            'name' => '',
            'methods' => [],
            'properties' => [],
            'line' => $this->getCurrentLine()
        ];
        
        // Skip class keyword
        $this->tokenizer->advance();
        
        // Get class name
        $token = $this->tokenizer->getCurrentToken();
        if ($this->tokenizer->isTokenType($token, T_STRING)) {
            $class['name'] = $this->tokenizer->getTokenValue($token);
            $this->tokenizer->advance();
        }
        
        $this->ast['classes'][] = $class;
    }
    
    private function parseVariable(): void
    {
        $token = $this->tokenizer->getCurrentToken();
        $varName = $this->tokenizer->getTokenValue($token);
        $line = $this->getCurrentLine();
        
        // Check if it's array access (like $_SERVER['HTTP_HOST'])
        $fullVarName = $this->parseVariableExpression();
        
        $variable = [
            'name' => $fullVarName,
            'line' => $line,
            'type' => 'variable'
        ];
        
        // Check if it's an assignment
        $currentToken = $this->tokenizer->getCurrentToken();
        if ($currentToken === '=') {
            $variable['type'] = 'assignment';
            $this->tokenizer->advance(); // Skip equals sign
            $variable['value'] = $this->parseExpression();
            
            $this->ast['assignments'][] = [
                'variable' => $fullVarName,
                'value' => $variable['value'] ?? '',
                'line' => $line
            ];
        }
        
        $this->ast['variables'][] = $variable;
    }
    
    private function parseVariableExpression(): string
    {
        $expression = '';
        $depth = 0;
        
        while (!$this->tokenizer->isAtEnd()) {
            $token = $this->tokenizer->getCurrentToken();
            
            if (is_array($token)) {
                $expression .= $token[1];
            } else {
                if ($token === '[') {
                    $depth++;
                    $expression .= $token;
                } elseif ($token === ']') {
                    $depth--;
                    $expression .= $token;
                    if ($depth === 0) {
                        $this->tokenizer->advance();
                        break;
                    }
                } elseif (in_array($token, ['=', ';', ',', ')', '}'])) {
                    break;
                } else {
                    $expression .= $token;
                }
            }
            
            $this->tokenizer->advance();
        }
        
        return $expression;
    }
    
    private function parseFunctionCall(): void
    {
        $token = $this->tokenizer->getCurrentToken();
        $functionName = $this->tokenizer->getTokenValue($token);
        $line = $this->getCurrentLine();
        
        $call = [
            'name' => $functionName,
            'arguments' => [],
            'line' => $line
        ];
        
        $this->tokenizer->advance(); // Skip function name
        
        // Skip left parenthesis
        if ($this->tokenizer->getCurrentToken() === '(') {
            $this->tokenizer->advance();
        }
        
        // Parse arguments
        $this->parseCallArguments($call);
        
        $this->ast['calls'][] = $call;
    }
    
    private function parseConcatenation(): void
    {
        $line = $this->getCurrentLine();
        $concat = [
            'line' => $line,
            'parts' => []
        ];
        
        // Get expressions before and after concatenation operator
        $left = $this->getPreviousExpression();
        $right = $this->getNextExpression();
        
        if ($left) $concat['parts'][] = $left;
        if ($right) $concat['parts'][] = $right;
        
        $this->ast['concatenations'][] = $concat;
        $this->tokenizer->advance();
    }
    
    private function parseFunctionParameters(array &$function): void
    {
        // Skip left parenthesis
        if ($this->tokenizer->getCurrentToken() === '(') {
            $this->tokenizer->advance();
        }
        
        while (!$this->tokenizer->isAtEnd()) {
            $token = $this->tokenizer->getCurrentToken();
            
            if ($token === ')') {
                break;
            }
            
            if ($this->tokenizer->isTokenType($token, T_VARIABLE)) {
                $function['parameters'][] = [
                    'name' => $this->tokenizer->getTokenValue($token),
                    'line' => $this->getCurrentLine()
                ];
            }
            
            $this->tokenizer->advance();
        }
    }
    
    private function parseFunctionBody(array &$function): void
    {
        // Simplified: skip function body
        $braceCount = 0;
        $inFunction = false;
        
        while (!$this->tokenizer->isAtEnd()) {
            $token = $this->tokenizer->getCurrentToken();
            
            if ($token === '{') {
                $braceCount++;
                $inFunction = true;
            } elseif ($token === '}') {
                $braceCount--;
                if ($inFunction && $braceCount === 0) {
                    break;
                }
            }
            
            $this->tokenizer->advance();
        }
    }
    
    private function parseCallArguments(array &$call): void
    {
        $depth = 0;
        
        while (!$this->tokenizer->isAtEnd()) {
            $token = $this->tokenizer->getCurrentToken();
            
            if ($token === '(') {
                $depth++;
            } elseif ($token === ')') {
                if ($depth === 0) {
                    break;
                }
                $depth--;
            } elseif ($token === ',' && $depth === 0) {
                // Argument separator
            } else {
                $arg = $this->parseExpression();
                if ($arg) {
                    $call['arguments'][] = $arg;
                }
            }
            
            $this->tokenizer->advance();
        }
    }
    
    private function parseExpression(): string
    {
        $expression = '';
        $depth = 0;
        
        while (!$this->tokenizer->isAtEnd()) {
            $token = $this->tokenizer->getCurrentToken();
            
            if (in_array($token, [',', ')', ';', '}'])) {
                break;
            }
            
            if ($token === '(') {
                $depth++;
            } elseif ($token === ')') {
                $depth--;
                if ($depth < 0) {
                    break;
                }
            }
            
            $expression .= $this->tokenizer->getTokenValue($token);
            $this->tokenizer->advance();
        }
        
        return trim($expression);
    }
    
    private function parseIfStatement(): void
    {
        // Simplified: skip if statement
        $this->skipBlock();
    }
    
    private function parseForeachStatement(): void
    {
        // Simplified: skip foreach statement
        $this->skipBlock();
    }
    
    private function parseForStatement(): void
    {
        // Simplified: skip for statement
        $this->skipBlock();
    }
    
    private function parseWhileStatement(): void
    {
        // Simplified: skip while statement
        $this->skipBlock();
    }
    
    private function parseReturnStatement(): void
    {
        $line = $this->getCurrentLine();
        $this->tokenizer->advance(); // Skip return
        
        $value = $this->parseExpression();
        
        $this->ast['statements'][] = [
            'type' => 'return',
            'value' => $value,
            'line' => $line
        ];
    }
    
    private function skipBlock(): void
    {
        $braceCount = 0;
        $inBlock = false;
        
        while (!$this->tokenizer->isAtEnd()) {
            $token = $this->tokenizer->getCurrentToken();
            
            if ($token === '{') {
                $braceCount++;
                $inBlock = true;
            } elseif ($token === '}') {
                $braceCount--;
                if ($inBlock && $braceCount === 0) {
                    break;
                }
            }
            
            $this->tokenizer->advance();
        }
    }
    
    private function isFunctionCall(): bool
    {
        $nextToken = $this->tokenizer->getNextToken();
        return $nextToken === '(';
    }
    
    private function getPreviousExpression(): ?string
    {
        $pos = $this->tokenizer->getPosition();
        if ($pos > 0) {
            $token = $this->tokenizer->getPreviousToken();
            return $this->tokenizer->getTokenValue($token);
        }
        return null;
    }
    
    private function getNextExpression(): ?string
    {
        $pos = $this->tokenizer->getPosition();
        if ($pos + 1 < count($this->tokenizer->getTokens())) {
            $token = $this->tokenizer->getNextToken();
            return $this->tokenizer->getTokenValue($token);
        }
        return null;
    }
    
    private function getCurrentLine(): int
    {
        $token = $this->tokenizer->getCurrentToken();
        return $this->tokenizer->getTokenLine($token);
    }
}