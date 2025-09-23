<?php
declare(strict_types=1);
namespace Hnp;
use Psalm\Plugin\PluginEntryPointInterface;
use Psalm\Plugin\RegistrationInterface;
use SimpleXMLElement;

final class HnpTaintPlugin implements PluginEntryPointInterface {
    public function __invoke(RegistrationInterface $registration, ?SimpleXMLElement $config = null): void {
        $registration->registerHooksFromClass(HnpHooks::class);
    }
}
