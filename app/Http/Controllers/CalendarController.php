<?php

namespace App\Http\Controllers;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Models\Event;
use App\Models\EventType;
use App\Models\Location;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The calendar page. Events themselves are loaded separately, for the visible
 * period only (see CalendarEventController). The page opens on the day, view and
 * filters (`instructor_id`, `event_type_id`) given in the address, so a reload
 * or a shared link shows the same calendar.
 */
class CalendarController extends Controller
{
    use ReadsCalendarQuery;

    public function __invoke(Request $request): Response
    {
        Gate::authorize('viewAny', Event::class);

        $date = $this->requestedDate($request->query('date'));
        $view = $this->requestedView($request->query('view'));

        return Inertia::render('calendar/Index', [
            'initialDate' => $date,
            'initialView' => $view,
            'initialFilters' => [
                'instructorId' => $request->query('instructor_id') === 'unassigned' ? 'unassigned' : $this->requestedId($request->query('instructor_id'), User::instructors()),
                'eventTypeId' => $this->requestedId($request->query('event_type_id'), EventType::query()),
            ],
            'instructors' => User::instructors()
                ->orderByDesc('is_active')
                ->orderBy('name')
                ->get()
                ->map(fn (User $instructor): array => [
                    'id' => $instructor->id,
                    'name' => $instructor->name,
                    'color' => $instructor->color,
                    'isActive' => $instructor->is_active,
                ]),
            'eventTypes' => EventType::inTreeOrder()->map(fn (EventType $eventType): array => [
                'id' => $eventType->id,
                'parentId' => $eventType->parent_id,
                'name' => $eventType->full_name,
                'shortName' => $eventType->name,
                'isActive' => $eventType->is_active,
            ]),
            'locations' => Location::query()
                ->active()
                ->orderBy('name')
                ->get(['name', 'address'])
                ->map(fn (Location $location): array => [
                    'name' => $location->name,
                    'address' => $location->address,
                ]),
            'statuses' => collect(EventStatus::cases())->map(fn (EventStatus $status): array => [
                'value' => $status->value,
                'label' => $status->label(),
            ]),
            'attendanceStatuses' => collect(AttendanceStatus::cases())->map(fn (AttendanceStatus $status): array => [
                'value' => $status->value,
                'label' => $status->label(),
                'isAttendanceMark' => $status->isAttendanceMark(),
            ]),
            'canCreate' => $request->user()->can('create', Event::class),
        ]);
    }
}
