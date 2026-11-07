<?php

namespace App\Events\Concerns;

use App\Actions\FindInstructorConflicts;
use App\Events\ChangeSet;
use App\Models\Equipment;
use App\Models\Event;
use App\Models\User;

/**
 * Wording shared by the descriptions of domain events.
 */
trait DescribesEvents
{
    /**
     * An event in the calendar as it reads in a notice: «Бассейн» 12.11 10:00–11:00.
     */
    protected static function calendarEventLabel(Event $event): string
    {
        return "«{$event->displayTitle()}» ".FindInstructorConflicts::period($event->starts_at, $event->ends_at);
    }

    /**
     * The day of the event in the calendar.
     */
    protected static function calendarUrl(Event $event): string
    {
        return route('calendar', ['view' => 'day', 'date' => $event->starts_at->format('Y-m-d')]);
    }

    /**
     * The lead instructor and the assistants of the event.
     *
     * @return list<int>
     */
    protected static function instructorIdsOf(Event $event): array
    {
        return $event->instructors()->pluck('users.id')->map(intval(...))->all();
    }

    /**
     * The changed attributes that have a label, by their labels, in the order of the labels:
     * "телефон, email". Null when none of the labelled attributes changed.
     *
     * @param  array<string, string>  $labels
     */
    protected static function changedLabels(ChangeSet $changes, array $labels): ?string
    {
        $changed = array_intersect_key($labels, array_flip($changes->attributes()));

        return $changed === [] ? null : implode(', ', $changed);
    }

    /**
     * The full names of the given users, separated by commas.
     *
     * @param  array<int, int>  $userIds
     */
    protected static function userNames(array $userIds): string
    {
        return User::query()->whereKey($userIds)->orderBy('name')->get()
            ->map(fn (User $user): string => $user->fullName())
            ->implode(', ');
    }

    /**
     * An item of equipment as it reads in a notice: «Регулятор» (R-001).
     */
    protected static function equipmentLabel(Equipment $equipment): string
    {
        return "«{$equipment->name}»".($equipment->inventory_number === null ? '' : " ({$equipment->inventory_number})");
    }

    /**
     * Where an administrator looks at an account: the instructor's page, or the account settings.
     */
    protected static function accountUrl(User $user): string
    {
        return $user->isInstructor() ? route('instructors.show', $user) : route('settings.users.edit', $user);
    }
}
