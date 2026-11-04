<?php

namespace Tests\Feature;

use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\EventType;
use App\Models\Exercise;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Exercises attached to a client on an event, from the event window of the calendar.
 */
class EventClientExerciseTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    #[DataProvider('everyRole')]
    public function test_every_role_attaches_several_exercises_to_a_client(bool $isAdmin): void
    {
        [$event, $client, $booking] = $this->booked();
        $mask = Exercise::factory()->offeredFor($event->type)->create(['name' => 'Снятие маски']);
        $ascent = Exercise::factory()->offeredFor($event->type)->create(['name' => 'Всплытие']);

        $this->actingAs($this->user($isAdmin))
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => [$mask->id, $ascent->id]])
            ->assertOk()
            ->assertJsonPath('data.0.exercises.0.name', 'Снятие маски')
            ->assertJsonPath('data.0.exercises.1.name', 'Всплытие');

        $this->assertEqualsCanonicalizing([$mask->id, $ascent->id], $booking->exercises()->pluck('exercises.id')->all());
    }

    public function test_attached_exercises_are_replaced_and_can_be_cleared(): void
    {
        [$event, $client, $booking] = $this->booked();
        $mask = Exercise::factory()->offeredFor($event->type)->create();
        $ascent = Exercise::factory()->offeredFor($event->type)->create();
        $booking->exercises()->attach([$mask->id, $ascent->id]);

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => [$ascent->id]])
            ->assertOk();
        $this->assertSame([$ascent->id], $booking->exercises()->pluck('exercises.id')->all());

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => []])
            ->assertOk()
            ->assertJsonPath('data.0.exercises', []);
        $this->assertSame(0, $booking->exercises()->count());
    }

    public function test_exercises_stay_when_the_request_does_not_mention_them(): void
    {
        [$event, $client, $booking] = $this->booked();
        $booking->exercises()->attach(Exercise::factory()->offeredFor($event->type)->create());

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'notes' => 'Заметка'])
            ->assertOk();

        $this->assertSame(1, $booking->exercises()->count());
    }

    public function test_exercises_of_one_client_do_not_touch_another(): void
    {
        [$event, $client] = $this->booked();
        $other = EventClient::factory()->forEvent($event)->create();
        $exercise = Exercise::factory()->offeredFor($event->type)->create();
        $other->exercises()->attach($exercise);

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => []])
            ->assertOk();

        $this->assertSame(1, $other->exercises()->count());
    }

    public function test_unknown_and_repeated_exercises_are_refused(): void
    {
        [$event, $client, $booking] = $this->booked();
        $exercise = Exercise::factory()->offeredFor($event->type)->create();

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => [999]])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('exercise_ids.0');
        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => [$exercise->id, $exercise->id]])
            ->assertUnprocessable();

        $this->assertSame(0, $booking->exercises()->count());
    }

    public function test_hidden_exercise_can_be_kept_but_not_newly_attached(): void
    {
        [$event, $client, $booking] = $this->booked();
        $kept = Exercise::factory()->hidden()->offeredFor($event->type)->create();
        $other = Exercise::factory()->hidden()->offeredFor($event->type)->create();
        $booking->exercises()->attach($kept);

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => [$kept->id]])
            ->assertOk()
            ->assertJsonPath('data.0.exercises.0.id', $kept->id);
        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => [$kept->id, $other->id]])
            ->assertUnprocessable();
    }

    public function test_listing_offers_only_active_exercises(): void
    {
        [$event] = $this->booked();
        Exercise::factory()->hidden()->offeredFor($event->type)->create();
        $active = Exercise::factory()->offeredFor($event->type)->create(['name' => 'Всплытие']);

        $this->actingAs($this->user(false))
            ->getJson("/events/{$event->id}/clients")
            ->assertOk()
            ->assertJsonCount(1, 'meta.exercises')
            ->assertJsonPath('meta.exercises.0', ['id' => $active->id, 'name' => 'Всплытие']);
    }

    public function test_listing_marks_exercises_the_client_did_on_other_events(): void
    {
        [$event, $client, $booking] = $this->booked();
        $mask = Exercise::factory()->offeredFor($event->type)->create();
        $ascent = Exercise::factory()->offeredFor($event->type)->create();
        $towing = Exercise::factory()->offeredFor($event->type)->create();
        $booking->exercises()->attach($towing);

        $earlier = EventClient::factory()->forEvent(Event::factory()->ledBy(User::factory()->create())->create())->forClient($client)->create();
        $earlier->exercises()->attach([$ascent->id, $towing->id]);

        $stranger = EventClient::factory()->forEvent($event)->create();
        EventClient::factory()->forEvent($earlier->event)->forClient($stranger->client)->create()->exercises()->attach($mask);

        $response = $this->actingAs($this->user(false))->getJson("/events/{$event->id}/clients")->assertOk();

        $rows = collect($response->json('data'))->keyBy('clientId');
        $this->assertEqualsCanonicalizing([$ascent->id, $towing->id], $rows[$client->id]['exerciseIdsDoneElsewhere']);
        $this->assertSame([$mask->id], $rows[$stranger->client_id]['exerciseIdsDoneElsewhere']);
    }

    public function test_listing_offers_exercises_of_the_event_type_and_of_its_parent(): void
    {
        $pool = EventType::factory()->create();
        $beginners = EventType::factory()->create(['parent_id' => $pool->id]);
        $advanced = EventType::factory()->create(['parent_id' => $pool->id]);
        $event = Event::factory()->ledBy(User::factory()->create())->create(['event_type_id' => $beginners->id]);

        $ofParent = Exercise::factory()->offeredFor($pool)->create();
        $ofType = Exercise::factory()->offeredFor($beginners, $advanced)->create();
        Exercise::factory()->offeredFor($advanced)->create();
        Exercise::factory()->offeredFor(EventType::factory()->create())->create();
        Exercise::factory()->create();

        $response = $this->actingAs($this->user(false))->getJson("/events/{$event->id}/clients")->assertOk();

        $this->assertSame([$ofParent->id, $ofType->id], array_column($response->json('meta.exercises'), 'id'));
    }

    public function test_parent_event_is_not_offered_exercises_of_its_children(): void
    {
        $pool = EventType::factory()->create();
        Exercise::factory()->offeredFor(EventType::factory()->create(['parent_id' => $pool->id]))->create();
        $event = Event::factory()->ledBy(User::factory()->create())->create(['event_type_id' => $pool->id]);

        $this->actingAs($this->user(false))
            ->getJson("/events/{$event->id}/clients")
            ->assertOk()
            ->assertJsonCount(0, 'meta.exercises');
    }

    public function test_exercise_of_another_type_can_be_kept_but_not_newly_attached(): void
    {
        [$event, $client, $booking] = $this->booked();
        $otherType = EventType::factory()->create();
        $kept = Exercise::factory()->offeredFor($otherType)->create();
        $other = Exercise::factory()->offeredFor($otherType)->create();
        $booking->exercises()->attach($kept);

        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => [$kept->id]])
            ->assertOk()
            ->assertJsonPath('data.0.exercises.0.id', $kept->id);
        $this->actingAs($this->user())
            ->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => [$kept->id, $other->id]])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('exercise_ids.1');

        $this->assertSame([$kept->id], $booking->exercises()->pluck('exercises.id')->all());
    }

    public function test_exercises_done_elsewhere_are_marked_only_when_offered_for_the_event(): void
    {
        [$event, $client] = $this->booked();
        $offered = Exercise::factory()->offeredFor($event->type)->create();
        $notOffered = Exercise::factory()->create();

        $earlier = EventClient::factory()->forEvent(Event::factory()->ledBy(User::factory()->create())->create())->forClient($client)->create();
        $earlier->exercises()->attach([$offered->id, $notOffered->id]);

        $this->actingAs($this->user(false))
            ->getJson("/events/{$event->id}/clients")
            ->assertOk()
            ->assertJsonPath('data.0.exerciseIdsDoneElsewhere', [$offered->id]);
    }

    public function test_guest_can_not_attach_exercises(): void
    {
        [$event, $client] = $this->booked();

        $this->patchJson("/events/{$event->id}/clients/{$client->id}", ['status' => 'booked', 'exercise_ids' => []])->assertUnauthorized();
    }

    /**
     * @return array{Event, Client, EventClient}
     */
    private function booked(): array
    {
        $event = Event::factory()->ledBy(User::factory()->create())->create();
        $client = Client::factory()->create();
        $booking = EventClient::factory()->forEvent($event)->forClient($client)->create();

        return [$event, $client, $booking];
    }

    private function user(bool $isAdmin = true): User
    {
        return $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
    }
}
