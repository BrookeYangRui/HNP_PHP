<?php
declare(strict_types=1);
namespace Hnp;
use PhpParser\Node;
use Psalm\Codebase;
use Psalm\Context;
use Psalm\Plugin\Hook\AfterExpressionAnalysisInterface;
use Psalm\StatementsSource;

final class HnpHooks implements AfterExpressionAnalysisInterface {
    public static function afterExpressionAnalysis(
        StatementsSource $statements_source,
        Node\Expr $expr,
        Context $context,
        Codebase $codebase
    ): ?bool {
        // Stub for future: mark $_SERVER['HTTP_HOST'] as tainted (kind: hnp),
        // recognize sinks header('Location: ...'), mail(), echo, etc.
        return null;
    }
}
