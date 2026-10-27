<?php

namespace App\Actions;

use App\Models\Event;
use App\Models\User;
use Carbon\CarbonInterface;
use Illuminate\Support\Collection;

/**
 * Finds other events that keep the given instructors busy during a period.
 * Cancelled events do not count. A conflict is only a warning: the event
 * can still be saved once the person has seen it.
 */
class FindInstructorConflicts
{
    /**
     * @param  list<int>  $instructorIds
     * @return Collection<int, array{eventId: int, instructor: string, title: string, time: string}>
     */
    public function handle(array $instructorIds, CarbonInterface $start, CarbonInterface $end, ?Event $ignore = null): Collection
    {
        if ($instructorIds === [] || $end->lessThanOrEqualTo($start)) {
            return collect();
        }

        $events = Event::query()
            ->with(['type', 'instructors' => fn ($query) => $query->whereKey($instructorIds)])
            ->overlapping($start, $end)
            ->notCancelled()
            ->whereHas('instructors', fn ($query) => $query->whereKey($instructorIds))
            ->when($ignore, fn ($query, Event $event) => $query->whereKeyNot($event->getKey()))
            ->orderBy('starts_at')
            ->get();

        return $events->flatMap(fn (Event $event): Collection => $event->instructors->map(fn (User $instructor): array => [
            'eventId' => $event->id,
            'instructor' => $instructor->name,
            'title' => $event->displayTitle(),
            'time' => self::period($event->starts_at, $event->ends_at),
        ]))->values();
    }

    /**
     * "28.10 10:00–11:30", or both dates when the event spans several days.
     */
    public static function period(CarbonInterface $start, CarbonInterface $end): string
    {
        if ($start->isSameDay($end)) {
            return $start->format('d.m H:i').'–'.$end->format('H:i');
        }

        return $start->format('d.m H:i').' – '.$end->format('d.m H:i');
    }
}
