<?php

namespace Tests\Feature;

use App\Models\Client;
use App\Models\Event;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * The permission table of the plan, screen by screen, for every kind of account.
 * An administrator who also teaches can do everything an administrator can.
 */
class RolePermissionsTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * Screen address, whether an administrator may open it, whether an instructor may.
     * `{person}` stands for another user's id, `{client}` for a client's id.
     *
     * @return array<string, array{string, bool, bool}>
     */
    public static function screens(): array
    {
        return [
            'calendar' => ['/calendar', true, true],
            'client list' => ['/clients', true, true],
            'new client' => ['/clients/create', true, true],
            'client card' => ['/clients/{client}', true, true],
            'edit client' => ['/clients/{client}/edit', true, true],
            'own profile' => ['/profile', true, true],
            'instructor list' => ['/instructors', true, false],
            'new instructor' => ['/instructors/create', true, false],
            'instructor card' => ['/instructors/{person}', true, false],
            'edit instructor' => ['/instructors/{person}/edit', true, false],
            'event types' => ['/settings/event-types', true, false],
            'user list' => ['/settings/users', true, false],
            'new user' => ['/settings/users/create', true, false],
            'edit user' => ['/settings/users/{person}/edit', true, false],
        ];
    }

    #[DataProvider('screens')]
    public function test_screens_are_open_to_the_roles_the_plan_names(string $address, bool $administratorMay, bool $instructorMay): void
    {
        $address = strtr($address, [
            '{person}' => (string) User::factory()->create()->id,
            '{client}' => (string) Client::factory()->create()->id,
        ]);

        $accounts = [
            'administrator' => [User::factory()->admin()->create(), $administratorMay],
            'instructor' => [User::factory()->create(), $instructorMay],
            'administrator who teaches' => [User::factory()->adminInstructor()->create(), $administratorMay],
        ];

        foreach ($accounts as $name => [$user, $mayOpen]) {
            $response = $this->actingAs($user)->get($address);

            $this->assertSame($mayOpen ? 200 : 403, $response->getStatusCode(), "Account: {$name}, screen: {$address}");
        }
    }

    public function test_only_administrators_delete_clients(): void
    {
        foreach ([true, false] as $isAdministrator) {
            $client = Client::factory()->create();
            $user = $isAdministrator ? User::factory()->admin()->create() : User::factory()->create();

            $response = $this->actingAs($user)->delete("/clients/{$client->id}");

            if ($isAdministrator) {
                $response->assertRedirect('/clients');
                $this->assertSoftDeleted($client);
            } else {
                $response->assertForbidden();
                $this->assertNotSoftDeleted($client);
            }
        }
    }

    public function test_administrator_who_teaches_deletes_clients(): void
    {
        $client = Client::factory()->create();

        $this->actingAs(User::factory()->adminInstructor()->create())->delete("/clients/{$client->id}")->assertRedirect('/clients');

        $this->assertSoftDeleted($client);
    }

    public function test_every_role_creates_edits_and_cancels_events_but_marks_attendance_only_on_own_ones(): void
    {
        $event = Event::factory()->ledBy(User::factory()->create())->create();
        $ownEvent = Event::factory()->ledBy($instructor = User::factory()->create())->create();
        $administrator = User::factory()->admin()->create();
        $teachingAdministrator = User::factory()->adminInstructor()->create();

        $this->assertTrue($instructor->can('create', Event::class));
        $this->assertTrue($instructor->can('update', $event));

        $this->assertFalse($instructor->can('markAttendance', $event));
        $this->assertTrue($instructor->can('markAttendance', $ownEvent));

        foreach ([$administrator, $teachingAdministrator] as $user) {
            $this->assertTrue($user->can('update', $event));
            $this->assertTrue($user->can('markAttendance', $event));
            $this->assertTrue($user->can('markAttendance', $ownEvent));
        }
    }
}
