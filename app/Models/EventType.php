<?php

namespace App\Models;

use Database\Factories\EventTypeFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

/**
 * A kind of activity in the calendar: theory, pool, open water and so on.
 * Administrators maintain the list; hidden types are not offered for new events.
 */
#[Fillable(['name', 'is_active'])]
class EventType extends Model
{
    /** @use HasFactory<EventTypeFactory> */
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
     * New types go to the end of the list.
     */
    protected static function booted(): void
    {
        static::creating(function (EventType $eventType): void {
            $eventType->sort_order ??= (int) static::query()->max('sort_order') + 1;
        });
    }

    /**
     * @param  Builder<EventType>  $query
     */
    #[Scope]
    protected function ordered(Builder $query): void
    {
        $query->orderBy('sort_order')->orderBy('id');
    }

    /**
     * @param  Builder<EventType>  $query
     */
    #[Scope]
    protected function active(Builder $query): void
    {
        $query->where('is_active', true);
    }

    /**
     * Move the type one place up the list. Does nothing when it is already first.
     */
    public function moveUp(): void
    {
        $this->moveBy(-1);
    }

    /**
     * Move the type one place down the list. Does nothing when it is already last.
     */
    public function moveDown(): void
    {
        $this->moveBy(1);
    }

    /**
     * Swap the type with its neighbour and renumber the whole list, so that
     * positions stay consecutive even if two types ever shared a number.
     */
    private function moveBy(int $offset): void
    {
        DB::transaction(function () use ($offset): void {
            $ids = static::query()->ordered()->lockForUpdate()->pluck('id')->all();

            $from = array_search($this->id, $ids, true);
            $to = $from === false ? null : $from + $offset;

            if ($to === null || ! array_key_exists($to, $ids)) {
                return;
            }

            [$ids[$from], $ids[$to]] = [$ids[$to], $ids[$from]];

            foreach ($ids as $index => $id) {
                static::query()->whereKey($id)->update(['sort_order' => $index + 1]);
            }
        });

        $this->refresh();
    }
}
