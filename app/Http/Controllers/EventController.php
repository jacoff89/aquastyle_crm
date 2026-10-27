<?php

namespace App\Http\Controllers;

use App\Actions\FindInstructorConflicts;
use App\Enums\EventStatus;
use App\Http\Requests\Events\EventRequest;
use App\Http\Requests\Events\StoreEventRequest;
use App\Http\Requests\Events\UpdateEventRequest;
use App\Http\Resources\CalendarEventResource;
use App\Models\Event;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;

/**
 * Creates and edits events from the calendar; moving and resizing an event is an edit too.
 *
 * When an instructor is already busy at that time, the event is not saved and the answer
 * is 409 with the clashing events. Sending the same data with `confirm_conflicts`
 * saves it anyway.
 */
class EventController extends Controller
{
    public function store(StoreEventRequest $request, FindInstructorConflicts $findConflicts): JsonResponse
    {
        if ($conflict = $this->conflictResponse($request, $findConflicts)) {
            return $conflict;
        }

        $event = DB::transaction(function () use ($request): Event {
            $event = new Event($request->eventAttributes());
            $event->status = EventStatus::Planned;
            $event->creator()->associate($request->user());
            $event->save();
            $event->assignInstructors($request->leadInstructorId(), $request->assistantIds());

            return $event;
        });

        return CalendarEventResource::make($event->load(['type', 'instructors']))
            ->response()
            ->setStatusCode(201);
    }

    public function update(UpdateEventRequest $request, Event $event, FindInstructorConflicts $findConflicts): JsonResponse
    {
        if ($this->schedulingChanges($request, $event) && $conflict = $this->conflictResponse($request, $findConflicts, $event)) {
            return $conflict;
        }

        DB::transaction(function () use ($request, $event): void {
            $event->fill($request->eventAttributes());
            $event->status = $request->status();
            $event->save();
            $event->assignInstructors($request->leadInstructorId(), $request->assistantIds());
        });

        return CalendarEventResource::make($event->load(['type', 'instructors']))->response();
    }

    /**
     * Whether the edit can put an instructor somewhere new: other times, other instructors,
     * or a cancelled event brought back. Editing only the notes of an event
     * that already overlaps another one does not warn again.
     */
    private function schedulingChanges(UpdateEventRequest $request, Event $event): bool
    {
        $currentIds = $event->instructors()->pluck('users.id')->sort()->values()->all();
        $newIds = collect($request->instructorIds())->sort()->values()->all();

        return ! $event->starts_at->equalTo($request->startsAt())
            || ! $event->ends_at->equalTo($request->endsAt())
            || $currentIds !== $newIds
            || ($event->status === EventStatus::Cancelled && $request->status() !== EventStatus::Cancelled);
    }

    private function conflictResponse(EventRequest $request, FindInstructorConflicts $findConflicts, ?Event $event = null): ?JsonResponse
    {
        if ($request->boolean('confirm_conflicts') || $request->status() === EventStatus::Cancelled) {
            return null;
        }

        $conflicts = $findConflicts->handle($request->instructorIds(), $request->startsAt(), $request->endsAt(), $event);

        if ($conflicts->isEmpty()) {
            return null;
        }

        return response()->json([
            'message' => 'Инструктор уже занят в это время.',
            'conflicts' => $conflicts,
        ], 409);
    }
}
