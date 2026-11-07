<?php

namespace App\Events;

use App\Models\User;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;

/**
 * Something was added, changed or removed in the CRM's data. Every application event implements it,
 * so a listener that type-hints this interface (the activity log, for one) receives all of them:
 * the dispatcher hands an event to the listeners of the interfaces it implements, not of its parent classes.
 *
 * Domain events are dispatched only after the database transaction around them commits,
 * so nothing is announced for a change that was rolled back.
 */
interface DomainEvent extends ShouldDispatchAfterCommit
{
    /**
     * Who made the change; null when it was made from the console.
     */
    public function actor(): ?User;

    /**
     * When the change was made. A queued listener runs later, so it must not use its own clock.
     */
    public function occurredAt(): CarbonImmutable;
}
