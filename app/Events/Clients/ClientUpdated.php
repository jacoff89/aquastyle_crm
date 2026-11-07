<?php

namespace App\Events\Clients;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\Client;
use App\Models\User;

/**
 * A client's details were changed.
 */
class ClientUpdated extends AbstractDomainEvent
{
    public function __construct(public Client $client, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the client changed. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(Client $client, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($client);

        if ($changes->isNotEmpty()) {
            static::dispatch($client, $changes, $actor);
        }
    }
}
