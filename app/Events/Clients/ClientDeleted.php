<?php

namespace App\Events\Clients;

use App\Events\AbstractDomainEvent;
use App\Models\Client;
use App\Models\User;

/**
 * A client was deleted. Clients are soft-deleted, so the model is still there
 * and a queued listener gets it back with its history.
 */
class ClientDeleted extends AbstractDomainEvent
{
    public function __construct(public Client $client, ?User $actor)
    {
        parent::__construct($actor);
    }
}
