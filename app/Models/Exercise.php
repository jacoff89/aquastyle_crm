<?php

namespace App\Models;

use App\Models\Concerns\HasListPosition;
use Database\Factories\ExerciseFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * A training exercise that is attached to a client on an event, e.g. «Снятие и надевание маски».
 * Administrators maintain the list and choose the event types each exercise is offered for.
 * Hidden exercises, and exercises not offered for the event's type, can not be newly attached
 * but stay on the bookings they were attached to.
 */
#[Fillable(['name', 'is_active'])]
class Exercise extends Model
{
    /** @use HasFactory<ExerciseFactory> */
    use HasFactory, HasListPosition;

    /**
     * @var array<string, mixed>
     */
    protected $attributes = [
        'is_active' => true,
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'sort_order' => 'integer',
            'is_active' => 'boolean',
        ];
    }

    /**
     * The event types the exercise is offered for. An exercise of a parent type
     * is offered for its children as well.
     *
     * @return BelongsToMany<EventType, $this>
     */
    public function eventTypes(): BelongsToMany
    {
        return $this->belongsToMany(EventType::class);
    }

    /**
     * @param  Builder<Exercise>  $query
     */
    #[Scope]
    protected function active(Builder $query): void
    {
        $query->where('is_active', true);
    }

    /**
     * Exercises offered for events of the given type: attached to the type itself or to its parent.
     *
     * @param  Builder<Exercise>  $query
     */
    #[Scope]
    protected function forEventType(Builder $query, EventType $eventType): void
    {
        $query->whereHas('eventTypes', fn (Builder $types) => $types->whereKey(array_filter([$eventType->id, $eventType->parent_id])));
    }
}
