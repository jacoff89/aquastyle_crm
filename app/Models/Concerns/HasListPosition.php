<?php

namespace App\Models\Concerns;

use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

/**
 * A record of a flat list that administrators put in order by hand, kept in `sort_order`.
 * New records go to the end of the list.
 *
 * @mixin Model
 */
trait HasListPosition
{
    /**
     * New records go to the end of the list.
     */
    protected static function bootHasListPosition(): void
    {
        static::creating(function (self $record): void {
            $record->sort_order ??= (int) static::query()->max('sort_order') + 1;
        });
    }

    /**
     * @param  Builder<static>  $query
     */
    #[Scope]
    protected function ordered(Builder $query): void
    {
        $query->orderBy($query->qualifyColumn('sort_order'))->orderBy($query->qualifyColumn('id'));
    }

    /**
     * Move the record one place up the list. Does nothing when it is already first.
     * Returns whether it moved.
     */
    public function moveUp(): bool
    {
        return $this->moveBy(-1);
    }

    /**
     * Move the record one place down the list. Does nothing when it is already last.
     * Returns whether it moved.
     */
    public function moveDown(): bool
    {
        return $this->moveBy(1);
    }

    /**
     * Swap the record with its neighbour and renumber the list, so that positions
     * stay consecutive even if two records ever shared a number.
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
