<?php

namespace App\Notifications\Telegram;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;

/**
 * The CRM's Telegram bot: a thin client of the Bot API with the settings from config/services.php.
 *
 * Requests go through `services.telegram.proxy` when it is set, because the server may not reach
 * api.telegram.org directly; the rest of the application does not use that proxy.
 */
class TelegramBot
{
    private const API_URL = 'https://api.telegram.org';

    /**
     * Whether the bot has a token and a username, so that it can send notices and be linked to.
     */
    public function isConfigured(): bool
    {
        return filled(config('services.telegram.token')) && filled(config('services.telegram.username'));
    }

    /**
     * The link that opens the bot with "/start <payload>" ready to send.
     */
    public function startLink(string $payload): string
    {
        return 'https://t.me/'.ltrim((string) config('services.telegram.username'), '@').'?start='.$payload;
    }

    /**
     * The secret Telegram sends back with every webhook request, so that nobody else can post updates.
     * Unless it is set in the environment, it is derived from the application key.
     */
    public function webhookSecret(): string
    {
        return (string) (config('services.telegram.webhook_secret') ?: hash_hmac('sha256', 'telegram-webhook', (string) config('app.key')));
    }

    /**
     * Send an HTML-formatted message to the chat.
     *
     * @throws TelegramException
     */
    public function sendMessage(int $chatId, string $html): void
    {
        $this->call('sendMessage', [
            'chat_id' => $chatId,
            'text' => $html,
            'parse_mode' => 'HTML',
            'link_preview_options' => ['is_disabled' => true],
        ]);
    }

    /**
     * Have Telegram post the bot's updates to the URL.
     *
     * @param  list<string>  $allowedUpdates
     *
     * @throws TelegramException
     */
    public function setWebhook(string $url, array $allowedUpdates): void
    {
        $this->call('setWebhook', [
            'url' => $url,
            'secret_token' => $this->webhookSecret(),
            'allowed_updates' => $allowedUpdates,
        ]);
    }

    /**
     * Stop posting updates to the webhook, so that they can be fetched with getUpdates.
     *
     * @throws TelegramException
     */
    public function deleteWebhook(): void
    {
        $this->call('deleteWebhook');
    }

    /**
     * The updates after the given one, waiting up to `$timeout` seconds for the first of them.
     *
     * @param  list<string>  $allowedUpdates
     * @return list<array<string, mixed>>
     *
     * @throws TelegramException
     */
    public function getUpdates(int $offset, int $timeout, array $allowedUpdates): array
    {
        return $this->call('getUpdates', [
            'offset' => $offset,
            'timeout' => $timeout,
            'allowed_updates' => $allowedUpdates,
        ], $timeout + 10);
    }

    /**
     * Call a Bot API method and return its result.
     *
     * @param  array<string, mixed>  $parameters
     *
     * @throws TelegramException
     */
    private function call(string $method, array $parameters = [], int $timeout = 10): mixed
    {
        $token = (string) config('services.telegram.token');

        try {
            $response = $this->request($timeout)->post(self::API_URL."/bot{$token}/{$method}", $parameters);
        } catch (ConnectionException $exception) {
            // The token is part of the URL that the message may quote; it must not reach the logs.
            throw new TelegramException('Telegram недоступен: '.str_replace($token, '***', $exception->getMessage()));
        }

        if ($response->json('ok') !== true) {
            throw new TelegramException(
                (string) ($response->json('description') ?? "HTTP {$response->status()}"),
                (int) ($response->json('error_code') ?? $response->status()),
                $response->json('parameters.retry_after'),
            );
        }

        return $response->json('result');
    }

    private function request(int $timeout): PendingRequest
    {
        $proxy = config('services.telegram.proxy');

        return Http::asJson()
            ->connectTimeout(5)
            ->timeout($timeout)
            ->when(filled($proxy), fn (PendingRequest $request) => $request->withOptions(['proxy' => $proxy]));
    }
}
