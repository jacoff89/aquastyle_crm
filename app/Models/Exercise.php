<?php

namespace App\Models;

use Database\Factories\ExerciseFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

/**
 * A training exercise that is attached to a client on an event, e.g. «Снятие и надевание маски».
 * Administrators maintain the list; hidden exercises are not offered for new attachments
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
     * @param  Builder<Exercise>  $query
     */
    #[Scope]
    protected function active(Builder $query): void
    {
        $query->where('is_active', true);
    }

    /**
     * Move the exercise one place up the list. Does nothing when it is already first.
     */
    public function moveUp(): void
    {
        $this->moveBy(-1);
    }

    /**
     * Move the exercise one place down the list. Does nothing when it is already last.
     */
    public function moveDown(): void
    {
        $this->moveBy(1);
    }

    /**
     * Swap the exercise with its neighbour and renumber the list, so that positions
     * stay consecutive even if two exercises ever shared a number.
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
