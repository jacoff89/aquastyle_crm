<?php

namespace App\Events;

/**
 * How a domain event reads to a person: one line of text, where to look at the change,
 * and whom it concerns besides the administrators. Notices are built from it.
 */
final class EventDescription
{
    /**
     * @var list<int>
     */
    public readonly array $concernedUserIds;

    /**
     * @param  string  $text  e.g. "Занятие «Бассейн» перенесено с 12.11 10:00–11:00 на 13.11 12:00–13:00"
     * @param  ?string  $url  the page where an administrator sees the change
     * @param  array<int, int|null>  $concernedUserIds  the users the change concerns; nulls are skipped
     * @param  ?string  $urlForConcerned  a page of their own for a concerned user who is not an administrator
     */
    public function __construct(
        public readonly string $text,
        public readonly ?string $url = null,
        array $concernedUserIds = [],
        public readonly ?string $urlForConcerned = null,
    ) {
        $this->concernedUserIds = array_values(array_unique(array_map(intval(...), array_filter($concernedUserIds, fn (mixed $id): bool => $id !== null))));
    }
}
