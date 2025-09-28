<?php
/**
 * Complete Lexical Analyzer
 * Based on PHP built-in token_get_all(), provides complete token stream analysis
 */

namespace HNP\Frontend;

class CompleteTokenizer
{
    private array $tokens = [];
    private string $currentFile = '';
    private int $position = 0;
    
    public function tokenize(string $file): array
    {
        $this->currentFile = $file;
        $this->position = 0;
        
        $content = file_get_contents($file);
        if ($content === false) {
            throw new \Exception("Cannot read file: $file");
        }
        
        $this->tokens = token_get_all($content);
        return $this->tokens;
    }
    
    public function getTokens(): array
    {
        return $this->tokens;
    }
    
    public function getCurrentToken(): array|string|null
    {
        return $this->tokens[$this->position] ?? null;
    }
    
    public function getNextToken(): array|string|null
    {
        return $this->tokens[$this->position + 1] ?? null;
    }
    
    public function getPreviousToken(): array|string|null
    {
        return $this->tokens[$this->position - 1] ?? null;
    }
    
    public function advance(): void
    {
        $this->position++;
    }
    
    public function isAtEnd(): bool
    {
        return $this->position >= count($this->tokens);
    }
    
    public function getPosition(): int
    {
        return $this->position;
    }
    
    public function setPosition(int $position): void
    {
        $this->position = $position;
    }
    
    public function getTokenValue($token): string
    {
        if (is_string($token)) {
            return $token;
        }
        return $token[1] ?? '';
    }
    
    public function getTokenType($token): int|string
    {
        if (is_string($token)) {
            return $token;
        }
        return $token[0] ?? '';
    }
    
    public function getTokenLine($token): int
    {
        if (is_string($token)) {
            return 0;
        }
        return $token[2] ?? 0;
    }
    
    public function isTokenType($token, int $type): bool
    {
        if (is_string($token)) {
            return false;
        }
        return $token[0] === $type;
    }
    
    public function isTokenString($token, string $string): bool
    {
        return $this->getTokenValue($token) === $string;
    }
    
    public function findTokens(int $type): array
    {
        $found = [];
        foreach ($this->tokens as $index => $token) {
            if ($this->isTokenType($token, $type)) {
                $found[] = ['index' => $index, 'token' => $token];
            }
        }
        return $found;
    }
    
    public function findTokenStrings(string $string): array
    {
        $found = [];
        foreach ($this->tokens as $index => $token) {
            if ($this->isTokenString($token, $string)) {
                $found[] = ['index' => $index, 'token' => $token];
            }
        }
        return $found;
    }
    
    public function getCurrentFile(): string
    {
        return $this->currentFile;
    }
}