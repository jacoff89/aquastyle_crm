<?php

namespace Tests\Feature;

use App\Models\User;
use App\Notifications\Telegram\TelegramLinkTokens;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

/**
 * The notification settings: linking Telegram and choosing which notices go there.
 * An instructor chooses among the notices that can concern them; an administrator among all,
 * with every notice of a type as an extra option.
 */
class NoticeSettingsControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config(['services.telegram.token' => 'test-token', 'services.telegram.username' => 'aquastyle_test_bot']);
        Http::preventStrayRequests();
        Http::fake(['api.telegram.org/*' => Http::response(['ok' => true, 'result' => []])]);
    }

    /**
     * @param  list<array{label: string, types: list<array{value: string}>}>  $groups
     * @return list<string>
     */
    private function typesIn(array $groups): array
    {
        return collect($groups)->flatMap(fn (array $group): array => array_column($group['types'], 'value'))->all();
    }

    public function test_guest_is_sent_to_the_login_page(): void
    {
        $this->get('/notifications/settings')->assertRedirect('/login');
        $this->put('/notifications/settings', ['choices' => []])->assertRedirect('/login');
        $this->post('/notifications/telegram')->assertRedirect('/login');
        $this->delete('/notifications/telegram')->assertRedirect('/login');
    }

    public function test_instructor_chooses_among_the_notices_that_can_concern_them(): void
    {
        $this->actingAs(User::factory()->create())
            ->get('/notifications/settings')
            ->assertOk()
            ->assertInertia(function (Assert $page): void {
                $page->component('notifications/Settings')
                    ->where('telegram.isConfigured', true)
                    ->where('telegram.isLinked', false)
                    ->where('telegram.linkUrl', null)
                    ->where('scopes', [['value' => 'mine', 'label' => 'Касающиеся меня']]);

                $types = $this->typesIn($page->toArray()['props']['groups']);
                $this->assertContains('CalendarEventRescheduled', $types);
                $this->assertContains('EquipmentAssigned', $types);
                $this->assertNotContains('ClientCreated', $types);

                // Until they choose, they get every type offered to them.
                $this->assertSame(array_fill_keys($types, 'mine'), $page->toArray()['props']['choices']);
            });
    }

    public function test_administrator_chooses_among_all_notices_and_can_ask_for_every_one(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->get('/notifications/settings')
            ->assertOk()
            ->assertInertia(function (Assert $page): void {
                $page->where('scopes.1.value', 'all');

                $this->assertContains('ClientCreated', $this->typesIn($page->toArray()['props']['groups']));
                $this->assertArrayNotHasKey('ClientCreated', $page->toArray()['props']['choices']);
            });
    }

    public function test_choices_are_saved(): void
    {
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->from('/notifications/settings')
            ->put('/notifications/settings', ['choices' => ['ClientCreated' => 'all', 'ClientBooked' => 'mine']])
            ->assertRedirect('/notifications/settings')
            ->assertSessionHas('status', 'Настройки уведомлений сохранены.');

        $this->assertSame(['ClientCreated' => 'all', 'ClientBooked' => 'mine'], $admin->refresh()->telegram_notices);
    }

    public function test_choosing_nothing_turns_every_notice_off(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->put('/notifications/settings', ['choices' => []])->assertSessionHasNoErrors();

        $this->actingAs($instructor)
            ->get('/notifications/settings')
            ->assertInertia(fn (Assert $page) => $page->where('choices', []));
    }

    public function test_instructor_cannot_choose_what_only_administrators_get(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs($instructor)
            ->put('/notifications/settings', ['choices' => ['ClientBooked' => 'all']])
            ->assertSessionHasErrors('choices.ClientBooked');

        $this->actingAs($instructor)
            ->put('/notifications/settings', ['choices' => ['ClientCreated' => 'mine']])
            ->assertSessionHasErrors('choices');

        $this->actingAs($instructor)
            ->put('/notifications/settings', ['choices' => ['NoSuchType' => 'mine']])
            ->assertSessionHasErrors('choices');

        $this->assertNull($instructor->refresh()->telegram_notices);
    }

    public function test_linking_gives_a_one_time_link_to_the_bot(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->from('/notifications/settings')->post('/notifications/telegram')->assertRedirect('/notifications/settings');

        $token = app(TelegramLinkTokens::class)->pendingFor($instructor);
        $this->assertNotNull($token);

        $this->actingAs($instructor)
            ->get('/notifications/settings')
            ->assertInertia(fn (Assert $page) => $page->where('telegram.linkUrl', "https://t.me/aquastyle_test_bot?start={$token}"));
    }

    public function test_linking_is_not_offered_while_the_bot_is_not_configured(): void
    {
        config(['services.telegram.username' => null]);
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->post('/notifications/telegram')->assertNotFound();
        $this->actingAs($instructor)
            ->get('/notifications/settings')
            ->assertInertia(fn (Assert $page) => $page->where('telegram.isConfigured', false));
    }

    public function test_unlinking_keeps_the_choices_and_says_goodbye_in_the_chat(): void
    {
        $instructor = User::factory()->withTelegram(['ClientBooked' => 'mine'])->create();
        $chatId = $instructor->telegram_chat_id;

        $this->actingAs($instructor)->delete('/notifications/telegram')->assertSessionHas('status', 'Telegram отключён.');

        $instructor->refresh();
        $this->assertFalse($instructor->hasTelegram());
        $this->assertSame(['ClientBooked' => 'mine'], $instructor->telegram_notices);
        Http::assertSent(fn (Request $request): bool => $request['chat_id'] === $chatId);
    }
}
