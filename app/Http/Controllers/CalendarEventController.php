<?php

namespace App\Http\Controllers;

use App\Http\Resources\CalendarEventResource;
use App\Models\Event;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Gate;

/**
 * Events for the period the calendar shows: every event that overlaps the days
 * from `start` to `end`, both inclusive. Cancelled events are included, the calendar
 * shows them faded.
 */
class CalendarEventController extends Controller
{
    private const MAX_DAYS = 62;

    public function __invoke(Request $request): AnonymousResourceCollection
    {
        Gate::authorize('viewAny', Event::class);

        $validated = $request->validate([
            'start' => ['required', 'date_format:Y-m-d'],
            'end' => ['required', 'date_format:Y-m-d', 'after_or_equal:start'],
        ]);

        $start = Carbon::createFromFormat('Y-m-d', $validated['start'])->startOfDay();
        $end = Carbon::createFromFormat('Y-m-d', $validated['end'])->addDay()->startOfDay();

        if ($start->diffInDays($end) > self::MAX_DAYS) {
            abort(422, 'Слишком большой период.');
        }

        $events = Event::query()
            ->with(['type', 'instructors'])
            ->overlapping($start, $end)
            ->orderBy('starts_at')
            ->orderBy('id')
            ->get();

        return CalendarEventResource::collection($events);
    }
}
