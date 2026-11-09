<?php

namespace Tests\Feature\Telegram;

use App\Models\User;
use App\Notifications\Telegram\TelegramBot;
use App\Notifications\Telegram\TelegramLinkTokens;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/**
 * The bot's webhook: "/start <token>" links the chat to the account the token was issued to,
 * "/stop" and blocking the bot unlink it, and only Telegram, knowing the secret, may post.
 */
class TelegramWebhookTest extends TestCase
{
    use LazilyRefreshDatabase;

    private const CHAT_ID = 555_000_111;

    protected function setUp(): void
    {
        parent::setUp();

        config(['services.telegram.token' => 'test-token', 'services.telegram.username' => 'aquastyle_test_bot']);
        Http::preventStrayRequests();
        Http::fake(['api.telegram.org/*' => Http::response(['ok' => true, 'result' => []])]);
    }

    /**
     * Post an update to the webhook the way Telegram does.
     *
     * @param  array<string, mixed>  $update
     */
    private function postUpdate(array $update, ?string $secret = null): TestResponse
    {
        return $this->postJson('/telegram/webhook', ['update_id' => 1, ...$update], [
            'X-Telegram-Bot-Api-Secret-Token' => $secret ?? app(TelegramBot::class)->webhookSecret(),
        ]);
    }

    /**
     * @return array{message: array<string, mixed>}
     */
    private function message(string $text, string $chatType = 'private'): array
    {
        return ['message' => [
            'message_id' => 10,
            'from' => ['id' => self::CHAT_ID, 'username' => 'ivan_diver'],
            'chat' => ['id' => self::CHAT_ID, 'type' => $chatType],
            'text' => $text,
        ]];
    }

    private function assertRepliedWith(string $fragment): void
    {
        Http::assertSent(fn (Request $request): bool => str_ends_with($request->url(), '/sendMessage')
            && $request['chat_id'] === self::CHAT_ID
            && str_contains($request['text'], $fragment));
    }

    public function test_a_request_without_the_secret_is_refused(): void
    {
        $this->postUpdate($this->message('/start'), 'wrong')->assertForbidden();
        $this->postJson('/telegram/webhook', $this->message('/start'))->assertForbidden();

        Http::assertNothingSent();
    }

    public function test_the_webhook_is_not_there_while_the_bot_is_not_configured(): void
    {
        config(['services.telegram.token' => null]);

        $this->postUpdate($this->message('/start'))->assertNotFound();
    }

    public function test_start_with_a_token_links_the_chat_to_its_account(): void
    {
        $instructor = User::factory()->create(['name' => 'Иван', 'last_name' => 'Петров']);
        $token = app(TelegramLinkTokens::class)->issueFor($instructor);

        $this->postUpdate($this->message("/start {$token}"))->assertNoContent();

        $instructor->refresh();
        $this->assertSame(self::CHAT_ID, $instructor->telegram_chat_id);
        $this->assertSame('ivan_diver', $instructor->telegram_username);
        $this->assertNull(app(TelegramLinkTokens::class)->pendingFor($instructor));
        $this->assertRepliedWith('Готово! Уведомления CRM для Иван Петров будут приходить сюда.');
    }

    public function test_a_token_works_once(): void
    {
        $instructor = User::factory()->create();
        $token = app(TelegramLinkTokens::class)->issueFor($instructor);
        $this->postUpdate($this->message("/start {$token}"));
        $instructor->unlinkTelegram();

        $this->postUpdate($this->message("/start {$token}"))->assertNoContent();

        $this->assertFalse($instructor->refresh()->hasTelegram());
        $this->assertRepliedWith('Ссылка устарела или уже использована.');
    }

    public function test_a_new_link_replaces_the_previous_one(): void
    {
        $instructor = User::factory()->create();
        $previous = app(TelegramLinkTokens::class)->issueFor($instructor);
        app(TelegramLinkTokens::class)->issueFor($instructor);

        $this->postUpdate($this->message("/start {$previous}"));

        $this->assertFalse($instructor->refresh()->hasTelegram());
    }

    public function test_the_chat_moves_from_the_account_that_had_it_before(): void
    {
        $before = User::factory()->create(['telegram_chat_id' => self::CHAT_ID]);
        $now = User::factory()->create();

        $this->postUpdate($this->message('/start '.app(TelegramLinkTokens::class)->issueFor($now)));

        $this->assertFalse($before->refresh()->hasTelegram());
        $this->assertSame(self::CHAT_ID, $now->refresh()->telegram_chat_id);
    }

    public function test_stop_unlinks_the_chat(): void
    {
        $instructor = User::factory()->create(['telegram_chat_id' => self::CHAT_ID]);

        $this->postUpdate($this->message('/stop'))->assertNoContent();

        $this->assertFalse($instructor->refresh()->hasTelegram());
        $this->assertRepliedWith('Уведомления отключены.');
    }

    public function test_blocking_the_bot_unlinks_the_chat(): void
    {
        $instructor = User::factory()->create(['telegram_chat_id' => self::CHAT_ID]);

        $this->postUpdate(['my_chat_member' => [
            'chat' => ['id' => self::CHAT_ID, 'type' => 'private'],
            'new_chat_member' => ['status' => 'kicked', 'user' => ['id' => 1]],
        ]])->assertNoContent();

        $this->assertFalse($instructor->refresh()->hasTelegram());
        Http::assertNothingSent();
    }

    public function test_any_other_message_gets_a_hint(): void
    {
        $this->postUpdate($this->message('привет'))->assertNoContent();

        $this->assertRepliedWith('нажмите «Подключить Telegram»');
    }

    public function test_group_chats_are_ignored(): void
    {
        $instructor = User::factory()->create();
        $token = app(TelegramLinkTokens::class)->issueFor($instructor);

        $this->postUpdate($this->message("/start {$token}", 'group'))->assertNoContent();

        $this->assertFalse($instructor->refresh()->hasTelegram());
        Http::assertNothingSent();
    }
}
