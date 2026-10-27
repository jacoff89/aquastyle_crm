<?php

namespace App\Http\Controllers;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Models\Event;
use App\Models\EventType;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The calendar page. Events themselves are loaded separately, for the visible
 * period only (see CalendarEventController).
 */
class CalendarController extends Controller
{
    private const VIEWS = ['month', 'week', 'day'];

    public function __invoke(Request $request): Response
    {
        Gate::authorize('viewAny', Event::class);

        $date = $this->requestedDate($request->query('date'));
        $view = in_array($request->query('view'), self::VIEWS, true) ? $request->query('view') : 'week';

        return Inertia::render('calendar/Index', [
            'initialDate' => $date,
            'initialView' => $view,
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
            'eventTypes' => EventType::query()->ordered()->get()->map(fn (EventType $eventType): array => [
                'id' => $eventType->id,
                'name' => $eventType->name,
                'isActive' => $eventType->is_active,
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
