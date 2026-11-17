<?php

namespace Tests\Feature;

use App\Models\User;
use App\Notifications\BirthdayReminderInTelegram;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

/**
 * Instructors keep their birthday, and the colleagues who linked Telegram are reminded of it three days ahead.
 */
class BirthdayReminderTest extends TestCase
{
    use LazilyRefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config(['services.telegram.token' => 'test-token', 'services.telegram.username' => 'aquastyle_test_bot']);
        $this->travelTo('2026-11-17 09:00');
        Notification::fake();
    }

    public function test_colleagues_with_telegram_are_reminded_three_days_ahead(): void
    {
        $birthdayPerson = User::factory()->withTelegram()->create(['birthday' => '1990-11-20']);
        $colleague = User::factory()->withTelegram()->create();
        $withoutTelegram = User::factory()->create();
        $inactive = User::factory()->withTelegram()->inactive()->create();

        $this->artisan('instructors:send-birthday-reminders')->assertSuccessful();

        Notification::assertSentTo($colleague, BirthdayReminderInTelegram::class, fn (BirthdayReminderInTelegram $reminder): bool => $reminder->birthdayPerson->is($birthdayPerson));
        Notification::assertNotSentTo([$birthdayPerson, $withoutTelegram, $inactive], BirthdayReminderInTelegram::class);
    }

    public function test_nobody_is_reminded_when_no_birthday_is_three_days_away(): void
    {
        User::factory()->withTelegram()->create(['birthday' => '1990-11-21']);
        User::factory()->withTelegram()->create(['birthday' => '1990-11-17']);
        User::factory()->withTelegram()->create();

        $this->artisan('instructors:send-birthday-reminders')->assertSuccessful();

        Notification::assertNothingSent();
    }

    public function test_an_inactive_instructor_is_not_congratulated(): void
    {
        User::factory()->inactive()->create(['birthday' => '1990-11-20']);
        User::factory()->withTelegram()->create();

        $this->artisan('instructors:send-birthday-reminders')->assertSuccessful();

        Notification::assertNothingSent();
    }

    public function test_nothing_is_sent_when_the_bot_is_not_configured(): void
    {
        config(['services.telegram.token' => null]);
        User::factory()->create(['birthday' => '1990-11-20']);
        User::factory()->withTelegram()->create();

        $this->artisan('instructors:send-birthday-reminders')->assertSuccessful();

        Notification::assertNothingSent();
    }

    public function test_a_leap_day_birthday_is_celebrated_on_the_28th_in_a_common_year(): void
    {
        $this->travelTo('2026-02-25 09:00');
        User::factory()->create(['birthday' => '1992-02-29']);
        $colleague = User::factory()->withTelegram()->create();

        $this->artisan('instructors:send-birthday-reminders')->assertSuccessful();

        Notification::assertSentTo($colleague, BirthdayReminderInTelegram::class);
    }

    public function test_the_message_names_the_colleague_and_the_day(): void
    {
        $birthdayPerson = User::factory()->create(['name' => 'Иван', 'last_name' => 'Петров']);

        $this->assertSame(
            '🎂 Иван Петров: день рождения через 3 дня.',
            (new BirthdayReminderInTelegram($birthdayPerson, 3))->toTelegram(User::factory()->make()),
        );
    }

    public function test_an_administrator_saves_the_birthday_of_an_instructor(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->put("/instructors/{$instructor->id}", [
                'name' => $instructor->name,
                'email' => $instructor->email,
                'color' => '#0891b2',
                'is_active' => true,
                'birthday' => '1990-03-05',
            ])
            ->assertRedirect();

        $this->assertSame('1990-03-05', $instructor->fresh()->birthday->toDateString());
    }

    public function test_a_birthday_in_the_future_is_rejected(): void
    {
        $this->actingAs(User::factory()->create())
            ->patch('/profile', ['name' => 'Иван', 'birthday' => '2027-01-01'])
            ->assertSessionHasErrors('birthday');
    }

    public function test_an_instructor_saves_their_own_birthday(): void
    {
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->patch('/profile', ['name' => 'Иван', 'birthday' => '1991-07-09'])->assertRedirect();

        $this->assertSame('1991-07-09', $instructor->fresh()->birthday->toDateString());
    }
}
