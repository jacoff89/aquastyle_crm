<?php

namespace App\Events\Clients;

use App\Events\AbstractDomainEvent;
use App\Models\Client;
use App\Models\User;

/**
 * A client was added: in the client directory or from the event window in the calendar.
 */
class ClientCreated extends AbstractDomainEvent
{
    public function __construct(public Client $client, ?User $actor)
    {
        parent::__construct($actor);
    }
}
