<?php

namespace App\Events\Communications;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Client;
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

    public function describe(): ?EventDescription
    {
        $client = Client::withTrashed()->findOrFail($this->communication->client_id);
        $channel = mb_strtolower($this->communication->channel->label());

        return new EventDescription(
            "Записан контакт с клиентом {$client->fullName()}: {$channel}, {$this->communication->occurred_at->format('d.m H:i')}",
            route('clients.show', $client->id),
        );
    }
}
