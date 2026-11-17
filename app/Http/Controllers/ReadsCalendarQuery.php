<?php

namespace App\Http\Controllers;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Reads the position a calendar page opens on from the address: the day, the view
 * and filter ids. Anything stale or mistyped is dropped, so such a link still opens
 * the page, just without that part.
 */
trait ReadsCalendarQuery
{
    /** @var list<string> */
    private const CALENDAR_VIEWS = ['month', 'week', 'day'];

    /**
     * The view to open; the month when the query has no known view.
     */
    private function requestedView(mixed $view): string
    {
        return in_array($view, self::CALENDAR_VIEWS, true) ? $view : 'month';
    }

    /**
     * The id from the query when it is a whole number of an existing record; null otherwise.
     *
     * @param  Builder<covariant Model>  $records
     */
    private function requestedId(mixed $id, Builder $records): ?int
    {
        if (! is_string($id) || filter_var($id, FILTER_VALIDATE_INT) === false) {
            return null;
        }

        return $records->whereKey((int) $id)->exists() ? (int) $id : null;
    }

    /**
     * The day to open, "Y-m-d"; today when the query has no valid date.
     */
    private function requestedDate(mixed $date): string
    {
        if (is_string($date) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) === 1) {
            $parsed = Carbon::createFromFormat('Y-m-d', $date);

            if ($parsed !== null && $parsed->format('Y-m-d') === $date) {
                return $date;
            }
        }

        return Carbon::today()->format('Y-m-d');
    }
}
