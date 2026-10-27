<?php

namespace App\Models;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Enums\InstructorRole;
use Carbon\CarbonInterface;
use Database\Factories\EventFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A class in the calendar. It has one lead instructor and any number of assistants;
 * its colour in the calendar is the lead instructor's colour. Clients are booked on it,
 * up to its capacity when it has one.
 *
 * Times are stored as wall-clock time in the application time zone.
 */
#[Fillable(['title', 'event_type_id', 'starts_at', 'ends_at', 'location', 'capacity', 'status', 'notes'])]
class Event extends Model
{
    /** @use HasFactory<EventFactory> */
    use HasFactory;

    /**
     * @var array<string, mixed>
     */
    protected $attributes = [
        'status' => 'planned',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'starts_at' => 'datetime',
            'ends_at' => 'datetime',
            'capacity' => 'integer',
            'status' => EventStatus::class,
        ];
    }

    /**
     * @return BelongsTo<EventType, $this>
     */
    public function type(): BelongsTo
    {
        return $this->belongsTo(EventType::class, 'event_type_id');
    }

    /**
     * Lead instructor and assistants; the part each one plays is in `pivot->role`.
     *
     * @return BelongsToMany<User, $this, EventInstructor, 'pivot'>
     */
    public function instructors(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'event_instructor')
            ->using(EventInstructor::class)
            ->withPivot('role');
    }

    /**
     * The clients booked on the event, with their attendance status.
     *
     * @return HasMany<EventClient, $this>
     */
    public function bookings(): HasMany
    {
        return $this->hasMany(EventClient::class);
    }

    /**
     * The user who created the event.
     *
     * @return BelongsTo<User, $this>
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * The title shown in the calendar: the event's own title, or its type when it has none.
     */
    public function displayTitle(): string
    {
        return filled($this->title) ? $this->title : (string) $this->type?->name;
    }

    /**
     * The lead instructor among the loaded instructors.
     */
    public function leadInstructor(): ?User
    {
        return $this->instructors->first(fn (User $instructor): bool => $instructor->pivot->role === InstructorRole::Lead);
    }

    /**
     * Replace the event's instructors with the given lead and assistants.
     * The lead is never also counted as an assistant.
     *
     * @param  list<int>  $assistantIds
     */
    public function assignInstructors(int $leadId, array $assistantIds = []): void
    {
        $instructors = [$leadId => ['role' => InstructorRole::Lead->value]];

        foreach (array_unique($assistantIds) as $assistantId) {
            if ($assistantId !== $leadId) {
                $instructors[$assistantId] = ['role' => InstructorRole::Assistant->value];
            }
        }

        $this->instructors()->sync($instructors);
        $this->unsetRelation('instructors');
    }

    /**
     * How many places are taken. A client who cancelled or did not come does not take one.
     */
    public function occupiedPlaces(): int
    {
        return $this->bookings()->whereIn('status', AttendanceStatus::occupyingValues())->count();
    }

    /**
     * Whether another client fits. An event without a capacity has no limit.
     */
    public function hasFreePlace(): bool
    {
        return $this->capacity === null || $this->occupiedPlaces() < $this->capacity;
    }

    /**
     * Events that share at least a minute with the given period. An event that ends
     * exactly when the period starts does not overlap it.
     *
     * @param  Builder<Event>  $query
     */
    #[Scope]
    protected function overlapping(Builder $query, CarbonInterface $start, CarbonInterface $end): void
    {
        $query->where('starts_at', '<', $end)->where('ends_at', '>', $start);
    }

    /**
     * @param  Builder<Event>  $query
     */
    #[Scope]
    protected function notCancelled(Builder $query): void
    {
        $query->where($query->qualifyColumn('status'), '!=', EventStatus::Cancelled->value);
    }

    /**
     * Events the given instructor takes part in, as lead or as assistant.
     *
     * @param  Builder<Event>  $query
     */
    #[Scope]
    protected function withInstructor(Builder $query, User|int $instructor): void
    {
        $id = $instructor instanceof User ? $instructor->getKey() : $instructor;

        $query->whereHas('instructors', fn (Builder $query) => $query->whereKey($id));
    }
}
