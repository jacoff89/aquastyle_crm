<?php

namespace Tests\Feature\Telegram;

use App\Models\EventType;
use App\Models\Notice;
use App\Models\User;
use App\Notifications\NoticeInTelegram;
use App\Notifications\Telegram\TelegramException;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

/**
 * Notices reach Telegram for the users who linked a chat and chose their type:
 * the ones that concern them, or every one for an administrator who asked for that.
 */
class TelegramNoticeDeliveryTest extends TestCase
{
    use LazilyRefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config(['services.telegram.token' => 'test-token', 'services.telegram.username' => 'aquastyle_test_bot']);
        Http::preventStrayRequests();
    }

    /**
     * Make the Bot API answer every request with the given body, a success by default.
     *
     * @param  array<string, mixed>  $body
     */
    private function fakeTelegram(array $body = ['ok' => true, 'result' => []], int $status = 200): void
    {
        Http::fake(['api.telegram.org/*' => Http::response($body, $status)]);
    }

    /**
     * @return list<int>
     */
    private function telegramRecipientIds(Notice $notice): array
    {
        return $notice->telegramRecipients()->pluck('id')->sort()->values()->all();
    }

    public function test_a_new_event_reaches_its_instructor_in_telegram_but_not_its_author(): void
    {
        $this->fakeTelegram();
        $admin = User::factory()->admin()->withTelegram(['CalendarEventCreated' => 'all'])->create(['name' => 'Анна', 'last_name' => null]);
        $lead = User::factory()->withTelegram()->create(['name' => 'Иван', 'last_name' => 'Петров']);

        $this->actingAs($admin)->postJson('/events', [
            'event_type_id' => EventType::factory()->create(['name' => 'Фридайвинг'])->id,
            'starts_at' => '2026-11-12 10:00',
            'ends_at' => '2026-11-12 11:00',
            'lead_instructor_id' => $lead->id,
        ])->assertCreated();

        Http::assertSentCount(1);
        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://api.telegram.org/bottest-token/sendMessage'
            && $request['chat_id'] === $lead->telegram_chat_id
            && $request['parse_mode'] === 'HTML'
            && str_contains($request['text'], 'Новое занятие «Фридайвинг» 12.11 10:00–11:00, ведущий Иван Петров')
            && str_contains($request['text'], 'Анна · '));
    }

    public function test_nothing_is_sent_while_the_bot_is_not_configured(): void
    {
        $this->fakeTelegram();
        config(['services.telegram.token' => null]);
        $lead = User::factory()->withTelegram()->create();

        $this->actingAs(User::factory()->admin()->create())->postJson('/events', [
            'event_type_id' => EventType::factory()->create()->id,
            'starts_at' => '2026-11-12 10:00',
            'ends_at' => '2026-11-12 11:00',
            'lead_instructor_id' => $lead->id,
        ])->assertCreated();

        Http::assertNothingSent();
    }

    public function test_by_default_a_user_gets_the_personal_notices_that_concern_them(): void
    {
        $instructor = User::factory()->withTelegram()->create();
        $other = User::factory()->withTelegram()->create();

        $theirs = Notice::factory()->concerning($instructor)->create(['type' => 'CalendarEventRescheduled']);
        $admins = Notice::factory()->create(['type' => 'ClientCreated']);

        $this->assertSame([$instructor->id], $this->telegramRecipientIds($theirs));
        $this->assertSame([], $this->telegramRecipientIds($admins));
        $this->assertNotContains($other->id, $this->telegramRecipientIds($theirs));
    }

    public function test_a_type_the_user_did_not_choose_is_not_sent(): void
    {
        $instructor = User::factory()->withTelegram(['ClientBooked' => 'mine'])->create();

        $chosen = Notice::factory()->concerning($instructor)->create(['type' => 'ClientBooked']);
        $notChosen = Notice::factory()->concerning($instructor)->create(['type' => 'CalendarEventRescheduled']);

        $this->assertSame([$instructor->id], $this->telegramRecipientIds($chosen));
        $this->assertSame([], $this->telegramRecipientIds($notChosen));
    }

    public function test_an_administrator_can_get_every_notice_of_a_type(): void
    {
        $everything = User::factory()->admin()->withTelegram(['ClientCreated' => 'all', 'ClientBooked' => 'mine'])->create();
        $byDefault = User::factory()->admin()->withTelegram()->create();

        $clientCreated = Notice::factory()->create(['type' => 'ClientCreated']);
        $someonesBooking = Notice::factory()->concerning(User::factory()->create())->create(['type' => 'ClientBooked']);

        $this->assertSame([$everything->id], $this->telegramRecipientIds($clientCreated));
        $this->assertSame([], $this->telegramRecipientIds($someonesBooking));
        $this->assertNotContains($byDefault->id, $this->telegramRecipientIds($clientCreated));
    }

    public function test_a_choice_the_users_roles_no_longer_allow_is_narrowed(): void
    {
        // Chosen while they were an administrator.
        $formerAdmin = User::factory()->withTelegram(['ClientBooked' => 'all', 'ClientCreated' => 'all'])->create();

        $someonesBooking = Notice::factory()->concerning(User::factory()->create())->create(['type' => 'ClientBooked']);
        $theirBooking = Notice::factory()->concerning($formerAdmin)->create(['type' => 'ClientBooked']);
        $clientCreated = Notice::factory()->concerning($formerAdmin)->create(['type' => 'ClientCreated']);

        $this->assertSame([], $this->telegramRecipientIds($someonesBooking));
        $this->assertSame([$formerAdmin->id], $this->telegramRecipientIds($theirBooking));
        $this->assertSame([], $this->telegramRecipientIds($clientCreated));
    }

    public function test_the_author_inactive_users_and_users_without_telegram_are_left_out(): void
    {
        $author = User::factory()->withTelegram()->create();
        $inactive = User::factory()->inactive()->withTelegram()->create();
        $withoutTelegram = User::factory()->create();

        $notice = Notice::factory()->concerning($author, $inactive, $withoutTelegram)->create([
            'type' => 'CalendarEventCancelled',
            'actor_id' => $author->id,
        ]);

        $this->assertSame([], $this->telegramRecipientIds($notice));
    }

    public function test_the_message_has_the_text_the_author_and_the_link_for_the_recipient(): void
    {
        $instructor = User::factory()->withTelegram()->create();
        $notice = Notice::factory()->concerning($instructor)->create([
            'type' => 'UserUpdated',
            'message' => 'Изменена учётная запись <Иван>: телефон',
            'url' => 'https://crm.test/settings/users/1/edit',
            'url_for_concerned' => 'https://crm.test/profile',
            'actor_id' => User::factory()->admin()->create(['name' => 'Анна', 'last_name' => 'Смирнова'])->id,
            'created_at' => '2026-11-09 18:30:00',
        ]);

        $this->assertSame(
            "Изменена учётная запись &lt;Иван&gt;: телефон\n\n<i>Анна Смирнова · 09.11.2026 18:30</i>\n<a href=\"https://crm.test/profile\">Открыть в CRM</a>",
            (new NoticeInTelegram($notice))->toTelegram($instructor),
        );
    }

    public function test_a_chat_that_blocked_the_bot_is_unlinked(): void
    {
        $this->fakeTelegram(['ok' => false, 'error_code' => 403, 'description' => 'Forbidden: bot was blocked by the user'], 403);
        $instructor = User::factory()->withTelegram(['ClientBooked' => 'mine'])->create();

        $instructor->notify(new NoticeInTelegram(Notice::factory()->concerning($instructor)->create(['type' => 'ClientBooked'])));

        $instructor->refresh();
        $this->assertFalse($instructor->hasTelegram());
        $this->assertSame(['ClientBooked' => 'mine'], $instructor->telegram_notices);
    }

    public function test_a_temporary_failure_is_thrown_so_that_the_queue_retries(): void
    {
        $this->fakeTelegram(['ok' => false, 'error_code' => 429, 'description' => 'Too Many Requests', 'parameters' => ['retry_after' => 5]], 429);
        $instructor = User::factory()->withTelegram()->create();

        try {
            $instructor->notify(new NoticeInTelegram(Notice::factory()->concerning($instructor)->create(['type' => 'ClientBooked'])));
            $this->fail('The failure was not thrown.');
        } catch (TelegramException $exception) {
            $this->assertSame(5, $exception->retryAfter);
        }

        $this->assertTrue($instructor->refresh()->hasTelegram());
    }
}
