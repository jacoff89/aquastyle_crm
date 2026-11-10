<?php

namespace Tests\Feature\Console;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\URL;
use Tests\TestCase;

/**
 * telegram:webhook points the bot's webhook at the site itself, or at the relay set in TELEGRAM_WEBHOOK_URL.
 */
class TelegramWebhookTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'services.telegram.token' => 'test-token',
            'services.telegram.username' => 'aquastyle_test_bot',
            'services.telegram.webhook_secret' => 'test-secret',
        ]);
        URL::forceRootUrl('https://crm.example.ru');
        URL::forceScheme('https');
    }

    private function assertWebhookSetTo(string $url): void
    {
        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://api.telegram.org/bottest-token/setWebhook'
            && $request['url'] === $url
            && $request['secret_token'] === 'test-secret');
    }

    public function test_sets_the_webhook_to_the_site_address_by_default(): void
    {
        Http::preventStrayRequests();
        Http::fake(['api.telegram.org/bottest-token/setWebhook' => Http::response(['ok' => true, 'result' => true])]);

        $this->artisan('telegram:webhook')
            ->expectsOutput('Webhook подключён: https://crm.example.ru/telegram/webhook')
            ->assertSuccessful();

        $this->assertWebhookSetTo('https://crm.example.ru/telegram/webhook');
    }

    public function test_sets_the_webhook_to_the_relay_address_when_it_is_configured(): void
    {
        config(['services.telegram.webhook_url' => 'https://tg.example.com/telegram/webhook']);
        Http::preventStrayRequests();
        Http::fake(['api.telegram.org/bottest-token/setWebhook' => Http::response(['ok' => true, 'result' => true])]);

        $this->artisan('telegram:webhook')
            ->expectsOutput('Webhook подключён: https://tg.example.com/telegram/webhook')
            ->assertSuccessful();

        $this->assertWebhookSetTo('https://tg.example.com/telegram/webhook');
    }
}
