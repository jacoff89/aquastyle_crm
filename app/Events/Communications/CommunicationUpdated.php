<?php

namespace App\Events\Communications;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\Communication;
use App\Models\User;

/**
 * A recorded contact with a client was edited.
 */
class CommunicationUpdated extends AbstractDomainEvent
{
    public function __construct(public Communication $communication, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the communication changed. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(Communication $communication, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($communication);

        if ($changes->isNotEmpty()) {
            static::dispatch($communication, $changes, $actor);
        }
    }
}
