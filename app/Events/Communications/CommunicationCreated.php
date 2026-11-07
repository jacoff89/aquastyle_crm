<?php

namespace App\Events\Communications;

use App\Events\AbstractDomainEvent;
use App\Models\Communication;
use App\Models\User;

/**
 * A contact with a client was recorded on the client's card.
 */
class CommunicationCreated extends AbstractDomainEvent
{
    public function __construct(public Communication $communication, ?User $actor)
    {
        parent::__construct($actor);
    }
}
