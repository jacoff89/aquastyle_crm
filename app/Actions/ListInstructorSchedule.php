<?php

namespace App\Actions;

use App\Enums\EventStatus;
use App\Enums\ScheduleRange;
use App\Models\Event;
use App\Models\User;
use Illuminate\Support\Carbon;

/**
 * The instructor's events from today for the chosen range, cancelled ones included,
 * shaped for the schedule block of the instructor's page and of their own profile.
 */
class ListInstructorSchedule
{
    /**
     * @return list<array{id: int, title: string, date: string, dateLabel: string, time: string, location: ?string, clientsCount: int, isCancelled: bool}>
     */
    public function handle(User $instructor, ScheduleRange $range): array
    {
        $from = Carbon::today();

        return Event::query()
            ->with('type')
            ->withOccupiedPlacesCount()
            ->withInstructor($instructor)
            ->overlapping($from, $range->endFrom($from))
            ->orderBy('starts_at')
            ->get()
            ->map(fn (Event $event): array => [
                'id' => $event->id,
                'title' => $event->displayTitle(),
                'date' => $event->starts_at->format('Y-m-d'),
                'dateLabel' => $event->starts_at->translatedFormat('D, j F'),
                'time' => $event->starts_at->format('H:i').'–'.$event->ends_at->format('H:i'),
                'location' => $event->location,
                'clientsCount' => (int) $event->occupied_places,
                'isCancelled' => $event->status === EventStatus::Cancelled,
            ])
            ->all();
    }
}
