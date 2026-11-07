<?php

namespace App\Models;

use Database\Factories\ExerciseFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\DB;

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
    use HasFactory;

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
     * New exercises go to the end of the list.
     */
    protected static function booted(): void
    {
        static::creating(function (Exercise $exercise): void {
            $exercise->sort_order ??= (int) static::query()->max('sort_order') + 1;
        });
    }

    /**
     * @param  Builder<Exercise>  $query
     */
    #[Scope]
    protected function ordered(Builder $query): void
    {
        $query->orderBy('sort_order')->orderBy('id');
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

    /**
     * Move the exercise one place up the list. Does nothing when it is already first.
     * Returns whether it moved.
     */
    public function moveUp(): bool
    {
        return $this->moveBy(-1);
    }

    /**
     * Move the exercise one place down the list. Does nothing when it is already last.
     * Returns whether it moved.
     */
    public function moveDown(): bool
    {
        return $this->moveBy(1);
    }

    /**
     * Swap the exercise with its neighbour and renumber the list, so that positions
     * stay consecutive even if two exercises ever shared a number.
     */
    private function moveBy(int $offset): bool
    {
        $moved = DB::transaction(function () use ($offset): bool {
            $ids = static::query()->ordered()->lockForUpdate()->pluck('id')->all();

            $from = array_search($this->id, $ids, true);
            $to = $from === false ? null : $from + $offset;

            if ($to === null || ! array_key_exists($to, $ids)) {
                return false;
            }

            [$ids[$from], $ids[$to]] = [$ids[$to], $ids[$from]];

            foreach ($ids as $index => $id) {
                static::query()->whereKey($id)->update(['sort_order' => $index + 1]);
            }

            return true;
        });

        $this->refresh();

        return $moved;
    }
}
