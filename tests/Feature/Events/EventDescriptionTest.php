<?php

namespace Tests\Feature\Events;

use App\Enums\AttendanceStatus;
use App\Enums\EquipmentStatus;
use App\Enums\EventStatus;
use App\Enums\Role;
use App\Events\Bookings\BookingExercisesChanged;
use App\Events\Bookings\BookingStatusChanged;
use App\Events\Bookings\BookingUpdated;
use App\Events\Bookings\ClientBooked;
use App\Events\CalendarEvents\CalendarEventCancelled;
use App\Events\CalendarEvents\CalendarEventCompleted;
use App\Events\CalendarEvents\CalendarEventCreated;
use App\Events\CalendarEvents\CalendarEventInstructorsChanged;
use App\Events\CalendarEvents\CalendarEventReopened;
use App\Events\CalendarEvents\CalendarEventRescheduled;
use App\Events\CalendarEvents\CalendarEventUpdated;
use App\Events\ChangeSet;
use App\Events\Clients\ClientCreated;
use App\Events\Clients\ClientDeleted;
use App\Events\Clients\ClientUpdated;
use App\Events\Communications\CommunicationCreated;
use App\Events\Communications\CommunicationDeleted;
use App\Events\Communications\CommunicationUpdated;
use App\Events\DomainEvent;
use App\Events\Equipment\EquipmentAssigned;
use App\Events\Equipment\EquipmentCategoryCreated;
use App\Events\Equipment\EquipmentCategoryUpdated;
use App\Events\Equipment\EquipmentCreated;
use App\Events\Equipment\EquipmentStatusChanged;
use App\Events\Equipment\EquipmentUpdated;
use App\Events\Settings\EventTypeCreated;
use App\Events\Settings\EventTypesReordered;
use App\Events\Settings\EventTypeUpdated;
use App\Events\Settings\ExerciseCreated;
use App\Events\Settings\ExerciseEventTypesChanged;
use App\Events\Settings\ExercisesReordered;
use App\Events\Settings\ExerciseUpdated;
use App\Events\Settings\LocationCreated;
use App\Events\Settings\LocationUpdated;
use App\Events\Users\UserActivated;
use App\Events\Users\UserCreated;
use App\Events\Users\UserDeactivated;
use App\Events\Users\UserPasswordChanged;
use App\Events\Users\UserRolesChanged;
use App\Events\Users\UserUpdated;
use App\Models\Client;
use App\Models\Communication;
use App\Models\Equipment;
use App\Models\EquipmentCategory;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\EventType;
use App\Models\Exercise;
use App\Models\Location;
use App\Models\User;
use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionClass;
use Tests\TestCase;

/**
 * Every domain event describes itself, so that it can become a notice.
 */
class EventDescriptionTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * The model after an update, with the change set of that update.
     *
     * @template TModel of Model
     *
     * @param  TModel  $model
     * @param  array<string, mixed>  $attributes
     * @return array{TModel, ChangeSet}
     */
    private static function updated(Model $model, array $attributes): array
    {
        $model->update($attributes);

        return [$model, ChangeSet::fromModel($model)];
    }

    /**
     * A way to build every domain event the application dispatches, keyed by its class.
     *
     * @return array<class-string<DomainEvent>, array{Closure(): DomainEvent}>
     */
    public static function everyEvent(): array
    {
        return [
            ClientCreated::class => [fn () => new ClientCreated(Client::factory()->create(), null)],
            ClientUpdated::class => [fn () => new ClientUpdated(...self::updated(Client::factory()->create(), ['notes' => 'Новая заметка']), actor: null)],
            ClientDeleted::class => [fn () => new ClientDeleted(Client::factory()->create(), null)],
            CommunicationCreated::class => [fn () => new CommunicationCreated(Communication::factory()->create(), null)],
            CommunicationUpdated::class => [fn () => new CommunicationUpdated(...self::updated(Communication::factory()->create(), ['notes' => 'Перезвонить']), actor: null)],
            CommunicationDeleted::class => [function () {
                $communication = Communication::factory()->create();

                return new CommunicationDeleted(ChangeSet::snapshotOf($communication->refresh()), $communication->client, null);
            }],
            CalendarEventCreated::class => [fn () => new CalendarEventCreated(Event::factory()->ledBy(User::factory()->create())->create(), null)],
            CalendarEventUpdated::class => [fn () => new CalendarEventUpdated(...self::updated(Event::factory()->create(), ['notes' => 'Взять грузы']), actor: null)],
            CalendarEventRescheduled::class => [fn () => new CalendarEventRescheduled(Event::factory()->create(), CarbonImmutable::parse('2026-11-12 10:00'), CarbonImmutable::parse('2026-11-12 11:00'), null)],
            CalendarEventCancelled::class => [fn () => new CalendarEventCancelled(Event::factory()->cancelled()->create(), EventStatus::Planned, null)],
            CalendarEventCompleted::class => [fn () => new CalendarEventCompleted(Event::factory()->done()->create(), EventStatus::Planned, null)],
            CalendarEventReopened::class => [fn () => new CalendarEventReopened(Event::factory()->create(), EventStatus::Cancelled, null)],
            CalendarEventInstructorsChanged::class => [function () {
                $lead = User::factory()->create();

                return new CalendarEventInstructorsChanged(Event::factory()->ledBy($lead)->create(), [$lead->id], [], [], null);
            }],
            ClientBooked::class => [fn () => new ClientBooked(EventClient::factory()->create(), null)],
            BookingUpdated::class => [fn () => new BookingUpdated(...self::updated(EventClient::factory()->create(), ['notes' => 'Нужны ласты']), actor: null)],
            BookingStatusChanged::class => [fn () => new BookingStatusChanged(EventClient::factory()->attended()->create(), AttendanceStatus::Booked, null)],
            BookingExercisesChanged::class => [fn () => new BookingExercisesChanged(EventClient::factory()->create(), [Exercise::factory()->create()->id], [], null)],
            UserCreated::class => [fn () => new UserCreated(User::factory()->create(), null)],
            UserUpdated::class => [fn () => new UserUpdated(...self::updated(User::factory()->create(), ['phone' => '+7 912 000-00-00']), actor: null)],
            UserActivated::class => [fn () => new UserActivated(User::factory()->create(), null)],
            UserDeactivated::class => [fn () => new UserDeactivated(User::factory()->inactive()->create(), null)],
            UserRolesChanged::class => [fn () => new UserRolesChanged(User::factory()->adminInstructor()->create(), [Role::Instructor], null)],
            UserPasswordChanged::class => [fn () => new UserPasswordChanged(User::factory()->create(), null)],
            EventTypeCreated::class => [fn () => new EventTypeCreated(EventType::factory()->create(), null)],
            EventTypeUpdated::class => [fn () => new EventTypeUpdated(...self::updated(EventType::factory()->create(), ['name' => 'Фридайвинг']), actor: null)],
            EventTypesReordered::class => [fn () => new EventTypesReordered(EventType::factory()->create(), 'up', null)],
            ExerciseCreated::class => [fn () => new ExerciseCreated(Exercise::factory()->create(), null)],
            ExerciseUpdated::class => [fn () => new ExerciseUpdated(...self::updated(Exercise::factory()->create(), ['name' => 'Всплытие с декомпрессией']), actor: null)],
            ExercisesReordered::class => [fn () => new ExercisesReordered(Exercise::factory()->create(), 'down', null)],
            ExerciseEventTypesChanged::class => [fn () => new ExerciseEventTypesChanged(Exercise::factory()->create(), [EventType::factory()->create()->id], [], null)],
            LocationCreated::class => [fn () => new LocationCreated(Location::factory()->create(), null)],
            LocationUpdated::class => [fn () => new LocationUpdated(...self::updated(Location::factory()->create(), ['address' => 'ул. Труда, 1']), actor: null)],
            EquipmentCreated::class => [fn () => new EquipmentCreated(Equipment::factory()->create(), null)],
            EquipmentUpdated::class => [fn () => new EquipmentUpdated(...self::updated(Equipment::factory()->create(), ['size' => 'XL']), actor: null)],
            EquipmentAssigned::class => [fn () => new EquipmentAssigned(Equipment::factory()->create(['instructor_id' => User::factory()->create()->id]), null, null)],
            EquipmentStatusChanged::class => [fn () => new EquipmentStatusChanged(Equipment::factory()->create(['status' => EquipmentStatus::Repair]), EquipmentStatus::InUse, null)],
            EquipmentCategoryCreated::class => [fn () => new EquipmentCategoryCreated(EquipmentCategory::factory()->create(), null)],
            EquipmentCategoryUpdated::class => [fn () => new EquipmentCategoryUpdated(...self::updated(EquipmentCategory::factory()->create(), ['name' => 'Компьютеры']), actor: null)],
        ];
    }

    /**
     * @param  Closure(): DomainEvent  $build
     */
    #[DataProvider('everyEvent')]
    public function test_every_event_describes_itself(Closure $build): void
    {
        $description = $build()->describe();

        $this->assertNotNull($description);
        $this->assertNotSame('', trim($description->text));
        $this->assertStringNotContainsString('{', $description->text);
    }

    public function test_every_domain_event_class_is_covered(): void
    {
        $classes = collect(glob(app_path('Events/*/*.php')))
            ->map(fn (string $path): string => 'App\\Events\\'.str_replace(['/', '.php'], ['\\', ''], substr($path, strlen(app_path('Events/')))))
            ->filter(fn (string $class): bool => is_subclass_of($class, DomainEvent::class) && ! (new ReflectionClass($class))->isAbstract())
            ->sort()
            ->values()
            ->all();

        $covered = collect(array_keys(self::everyEvent()))->sort()->values()->all();

        $this->assertSame($classes, $covered);
    }
}
