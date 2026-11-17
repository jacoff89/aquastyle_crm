<?php

namespace Tests\Feature;

use App\Models\Communication;
use App\Models\Notice;
use App\Models\User;
use App\Notifications\NoticeInTelegram;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

/**
 * A planned communication whose time has come is announced once: a notice, and a message in Telegram.
 */
class CommunicationReminderTest extends TestCase
{
    use LazilyRefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config(['services.telegram.token' => 'test-token', 'services.telegram.username' => 'aquastyle_test_bot', 'services.telegram.deliver' => true]);
        $this->travelTo('2026-11-17 12:00');
    }

    public function test_due_planned_communication_creates_a_notice_for_its_author_and_goes_to_telegram(): void
    {
        Notification::fake();
        $author = User::factory()->withTelegram()->create();
        $admin = User::factory()->admin()->create();
        $other = User::factory()->withTelegram()->create();
        $communication = Communication::factory()->planned()->create(['created_by' => $author->id, 'occurred_at' => '2026-11-17 11:59', 'notes' => 'Напомнить про оплату']);

        $this->artisan('communications:send-reminders')->assertSuccessful();

        $notice = Notice::sole();
        $this->assertSame('CommunicationDue', $notice->type);
        $this->assertStringContainsString('Напомнить про оплату', $notice->message);
        $this->assertTrue($notice->isVisibleTo($author));
        $this->assertTrue($notice->isVisibleTo($admin));
        $this->assertFalse($notice->isVisibleTo($other));
        $this->assertNotNull($communication->fresh()->reminded_at);
        Notification::assertSentTo($author, NoticeInTelegram::class);
        Notification::assertNotSentTo($other, NoticeInTelegram::class);
    }

    public function test_communication_is_announced_only_once(): void
    {
        Communication::factory()->planned()->create(['occurred_at' => '2026-11-17 11:00']);

        $this->artisan('communications:send-reminders')->assertSuccessful();
        $this->artisan('communications:send-reminders')->assertSuccessful();

        $this->assertSame(1, Notice::count());
    }

    public function test_future_and_completed_communications_are_not_announced(): void
    {
        Communication::factory()->planned()->create(['occurred_at' => '2026-11-17 12:01']);
        Communication::factory()->create(['occurred_at' => '2026-11-17 11:00']);

        $this->artisan('communications:send-reminders')->assertSuccessful();

        $this->assertSame(0, Notice::count());
    }

    public function test_rescheduling_makes_the_reminder_due_again(): void
    {
        $communication = Communication::factory()->planned()->create(['occurred_at' => '2026-11-17 11:00']);
        $this->artisan('communications:send-reminders')->assertSuccessful();

        $communication->update(['occurred_at' => '2026-11-17 11:30']);
        $this->artisan('communications:send-reminders')->assertSuccessful();

        $this->assertSame(2, Notice::where('type', 'CommunicationDue')->count());
    }
}
