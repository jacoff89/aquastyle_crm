<?php

namespace App\Events\Communications;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Client;
use App\Models\Communication;

/**
 * The time of a planned contact with a client has come. It is announced by the console,
 * so it has no author; the user who planned the contact is the one it concerns.
 */
class CommunicationDue extends AbstractDomainEvent
{
    public function __construct(public Communication $communication)
    {
        parent::__construct(null);
    }

    public function describe(): ?EventDescription
    {
        $client = Client::withTrashed()->findOrFail($this->communication->client_id);
        $channel = mb_strtolower($this->communication->channel->label());
        $url = route('clients.show', $client->id);

        return new EventDescription(
            "Пора связаться с клиентом {$client->fullName()}: {$channel}, {$this->communication->occurred_at->format('d.m H:i')}. {$this->communication->notes}",
            $url,
            [$this->communication->created_by],
            $url,
        );
    }
}
