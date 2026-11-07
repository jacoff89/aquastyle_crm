<?php

namespace Tests\Feature;

use App\Models\Notice;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

/**
 * The notifications page: administrators see every notice, instructors only the ones that concern them.
 */
class NoticeControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_guest_is_sent_to_the_login_page(): void
    {
        $notice = Notice::factory()->create();

        $this->get('/notifications')->assertRedirect('/login');
        $this->post("/notifications/{$notice->id}/open")->assertRedirect('/login');
        $this->post('/notifications/read-all')->assertRedirect('/login');
    }

    public function test_administrator_sees_every_notice_newest_first(): void
    {
        $instructor = User::factory()->create();
        $older = Notice::factory()->concerning($instructor)->create(['message' => 'Старое', 'created_at' => now()->subDay()]);
        $newer = Notice::factory()->create(['message' => 'Новое']);

        $this->actingAs(User::factory()->admin()->create())
            ->get('/notifications')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('notifications/Index')
                ->has('notices.data', 2)
                ->where('notices.data.0.id', $newer->id)
                ->where('notices.data.0.isRead', false)
                ->where('notices.data.1.id', $older->id)
                ->where('hasUnread', true));
    }

    public function test_instructor_sees_only_the_notices_that_concern_them(): void
    {
        $instructor = User::factory()->create();
        $theirs = Notice::factory()->concerning($instructor)->create();
        Notice::factory()->concerning(User::factory()->create())->create();
        Notice::factory()->create();

        $this->actingAs($instructor)
            ->get('/notifications')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->has('notices.data', 1)
                ->where('notices.data.0.id', $theirs->id));
    }

    public function test_unread_filter_leaves_out_read_notices(): void
    {
        $admin = User::factory()->admin()->create();
        $unread = Notice::factory()->create();
        Notice::factory()->readBy($admin)->create();

        $this->actingAs($admin)
            ->get('/notifications?filter=unread')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->where('filter', 'unread')
                ->has('notices.data', 1)
                ->where('notices.data.0.id', $unread->id));
    }

    public function test_opening_a_notice_marks_it_read_and_leads_to_the_change(): void
    {
        $admin = User::factory()->admin()->create();
        $notice = Notice::factory()->create(['url' => '/clients/5']);

        $this->actingAs($admin)->post("/notifications/{$notice->id}/open")->assertRedirect('/clients/5');

        $this->assertTrue($notice->readers()->whereKey($admin->id)->exists());
    }

    public function test_a_concerned_instructor_is_led_to_their_own_page_when_the_notice_has_one(): void
    {
        $instructor = User::factory()->create();
        $notice = Notice::factory()->concerning($instructor)->create(['url' => "/instructors/{$instructor->id}", 'url_for_concerned' => '/profile']);

        $this->actingAs($instructor)->post("/notifications/{$notice->id}/open")->assertRedirect('/profile');
        $this->actingAs(User::factory()->admin()->create())->post("/notifications/{$notice->id}/open")->assertRedirect("/instructors/{$instructor->id}");
    }

    public function test_opening_a_notice_without_a_page_goes_back(): void
    {
        $admin = User::factory()->admin()->create();
        $notice = Notice::factory()->create(['url' => null]);

        $this->actingAs($admin)->from('/notifications')->post("/notifications/{$notice->id}/open")->assertRedirect('/notifications');
    }

    public function test_instructor_can_not_open_a_notice_that_does_not_concern_them(): void
    {
        $instructor = User::factory()->create();
        $notice = Notice::factory()->create();

        $this->actingAs($instructor)->post("/notifications/{$notice->id}/open")->assertForbidden();

        $this->assertFalse($notice->readers()->exists());
    }

    public function test_reading_all_marks_only_the_notices_the_user_sees(): void
    {
        $instructor = User::factory()->create();
        $theirs = Notice::factory()->concerning($instructor)->count(2)->create();
        Notice::factory()->concerning($instructor)->readBy($instructor)->create();
        $others = Notice::factory()->create();

        $this->actingAs($instructor)->from('/notifications')->post('/notifications/read-all')->assertRedirect('/notifications');

        $this->assertSame(0, Notice::unreadCountFor($instructor));
        $this->assertTrue($theirs->every(fn (Notice $notice): bool => $notice->readers()->whereKey($instructor->id)->exists()));
        $this->assertDatabaseCount('notice_reads', 3);
        $this->assertFalse($others->readers()->exists());
    }

    public function test_every_page_shares_the_unread_count_of_the_user(): void
    {
        $instructor = User::factory()->create();
        Notice::factory()->concerning($instructor)->count(2)->create();
        Notice::factory()->concerning($instructor)->readBy($instructor)->create();
        Notice::factory()->create();

        $this->actingAs($instructor)
            ->get('/calendar')
            ->assertInertia(fn (Assert $page) => $page->where('unreadNotices', 2));
    }

    public function test_unread_count_stops_at_the_cap(): void
    {
        $admin = User::factory()->admin()->create();
        Notice::factory()->count(Notice::UNREAD_COUNT_CAP + 1)->create();

        $this->assertSame(Notice::UNREAD_COUNT_CAP, Notice::unreadCountFor($admin));
    }
}
