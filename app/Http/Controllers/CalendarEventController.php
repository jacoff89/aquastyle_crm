<?php

namespace App\Http\Controllers;

use App\Enums\Role;
use App\Http\Resources\CalendarEventResource;
use App\Models\Event;
use App\Models\EventType;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

/**
 * Events for the period the calendar shows: every event that overlaps the days
 * from `start` to `end`, both inclusive. Cancelled events are included, the calendar
 * shows them faded.
 *
 * The calendar can be narrowed to one instructor (lead or assistant) with `instructor_id`
 * and to one event type with `event_type_id`. Deactivated instructors and hidden types
 * can be filtered by too: their past events stay in the calendar.
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
            'instructor_id' => ['nullable', 'integer', Rule::exists(User::class, 'id')->where(
                fn (QueryBuilder $query) => $query->whereJsonContains('roles', Role::Instructor->value),
            )],
            'event_type_id' => ['nullable', 'integer', Rule::exists(EventType::class, 'id')],
        ]);

        $start = Carbon::createFromFormat('Y-m-d', $validated['start'])->startOfDay();
        $end = Carbon::createFromFormat('Y-m-d', $validated['end'])->addDay()->startOfDay();

        if ($start->diffInDays($end) > self::MAX_DAYS) {
            abort(422, 'Слишком большой период.');
        }

        $events = Event::query()
            ->with(['type', 'instructors'])
            ->overlapping($start, $end)
            ->when($request->filled('instructor_id'), fn (Builder $query) => $query->withInstructor($request->integer('instructor_id')))
            ->when($request->filled('event_type_id'), fn (Builder $query) => $query->where('event_type_id', $request->integer('event_type_id')))
            ->orderBy('starts_at')
            ->orderBy('id')
            ->get();

        return CalendarEventResource::collection($events);
    }
}
