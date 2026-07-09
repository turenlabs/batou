<?php
/**
 * Fixture: ownCloud-style @PublicPage controller method with classic SSRF.
 *
 * Mirrors the real apps/files_sharing/.../ExternalSharesController::testRemote
 * shape that batou's BATOU-OWNCLOUD-AST-001 rule is built to catch:
 *
 *   - public, unauthenticated route via @PublicPage docblock
 *   - $remote parameter flows directly into IClientService / Guzzle
 *   - no scheme allowlist, no private-IP filter
 *
 * Expected finding: BATOU-OWNCLOUD-AST-001 (CWE-918, Critical) on the
 * member_call_expression line.
 */

namespace OCA\Files_Sharing\Controllers;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\DataResponse;
use OCP\Http\Client\IClientService;
use OCP\IRequest;

class ExternalSharesController extends Controller {
    /** @var IClientService */
    private $clientService;

    public function __construct($appName, IRequest $request, IClientService $clientService) {
        parent::__construct($appName, $request);
        $this->clientService = $clientService;
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     *
     * @param string $remote
     * @return DataResponse
     */
    public function testRemote($remote) {
        $url = "https://" . $remote . "/ocs-provider/";
        $client = $this->clientService->newClient();
        $response = $client->get($url);
        return new DataResponse($response->getBody());
    }

    /**
     * @PublicPage
     * Direct curl_setopt SSRF.
     */
    public function probe($u) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $u);
        curl_exec($ch);
    }

    #[\OCP\AppFramework\Http\Attribute\PublicPage]
    public function fetchAttr($host) {
        return file_get_contents("https://" . $host . "/.well-known/x");
    }
}
