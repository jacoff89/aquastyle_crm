<?php

namespace Tests\Feature\Events;

use App\Enums\EventStatus;
use App\Enums\Role;
use App\Events\ChangeSet;
use App\Models\Client;
use App\Models\Communication;
use App\Models\Event;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

/**
 * The change set of one save: old and new values in a plain form that can be queued and stored.
 */
class ChangeSetTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_it_holds_old_and_new_values_of_the_changed_attributes_in_plain_form(): void
    {
        $event = Event::factory()->at('2026-11-10 10:00', '2026-11-10 11:00')->create(['notes' => 'Взять маски']);

        $event->update([
            'starts_at' => '2026-11-12 18:00',
            'ends_at' => '2026-11-12 19:30',
            'status' => EventStatus::Cancelled,
        ]);

        $this->assertEquals([
            'starts_at' => ['old' => '2026-11-10 10:00:00', 'new' => '2026-11-12 18:00:00'],
            'ends_at' => ['old' => '2026-11-10 11:00:00', 'new' => '2026-11-12 19:30:00'],
            'status' => ['old' => 'planned', 'new' => 'cancelled'],
        ], ChangeSet::fromModel($event)->toArray());
    }

    public function test_a_save_that_changed_nothing_gives_an_empty_change_set(): void
    {
        $client = Client::factory()->create(['first_name' => 'Пётр']);

        $client->update(['first_name' => 'Пётр']);

        $this->assertTrue(ChangeSet::fromModel($client)->isEmpty());
    }

    public function test_secrets_and_derived_columns_are_left_out(): void
    {
        $user = User::factory()->create();
        $client = Client::factory()->create(['phone' => '+7 912 345-67-89']);

        $user->update(['password' => 'new-secret-password', 'remember_token' => 'another-token']);
        $client->update(['phone' => '8 (900) 000-00-00']);

        $this->assertTrue(ChangeSet::fromModel($user)->isEmpty());
        $this->assertSame(['phone'], ChangeSet::fromModel($client)->attributes());
    }

    public function test_an_enum_collection_is_kept_as_a_list_of_values(): void
    {
        $user = User::factory()->create(['roles' => [Role::Instructor]]);

        $user->update(['roles' => [Role::Admin, Role::Instructor]]);

        $changes = ChangeSet::fromModel($user);

        $this->assertSame(['instructor'], $changes->old('roles'));
        $this->assertSame(['admin', 'instructor'], $changes->new('roles'));
    }

    public function test_a_stored_change_set_reads_back_the_same(): void
    {
        $event = Event::factory()->create(['capacity' => 4]);
        $event->update(['capacity' => 6]);
        $changes = ChangeSet::fromModel($event);

        $restored = ChangeSet::fromArray(json_decode(json_encode($changes), true));

        $this->assertSame($changes->toArray(), $restored->toArray());
        $this->assertTrue($restored->has('capacity'));
        $this->assertSame(6, $restored->new('capacity'));
    }

    public function test_snapshot_keeps_a_records_attributes_in_the_same_plain_form(): void
    {
        $communication = Communication::factory()->create(['channel' => 'phone', 'occurred_at' => '2026-11-03 14:30', 'notes' => 'Перезвонить']);

        $snapshot = ChangeSet::snapshotOf($communication->refresh());

        $this->assertSame('phone', $snapshot['channel']);
        $this->assertSame('2026-11-03 14:30:00', $snapshot['occurred_at']);
        $this->assertSame($communication->client_id, $snapshot['client_id']);
        $this->assertArrayNotHasKey('created_at', $snapshot);
    }
}
