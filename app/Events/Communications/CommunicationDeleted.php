<?php

namespace App\Events\Communications;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\Client;
use App\Models\Communication;
use App\Models\User;
use Carbon\CarbonImmutable;

/**
 * A recorded contact with a client was deleted. Communications are deleted for good, so a queued
 * listener could not load the model back; the event carries a snapshot of its attributes instead.
 */
class CommunicationDeleted extends AbstractDomainEvent
{
    /**
     * @param  array<string, mixed>  $snapshot  the communication's attributes, see ChangeSet::snapshotOf()
     */
    public function __construct(public array $snapshot, public Client $client, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce the deletion with a snapshot of the communication, which keeps its attributes in memory after delete().
     */
    public static function dispatchFor(Communication $communication, ?User $actor): void
    {
        $client = Client::withTrashed()->findOrFail($communication->client_id);

        static::dispatch(ChangeSet::snapshotOf($communication), $client, $actor);
    }

    public function describe(): ?EventDescription
    {
        $occurredAt = CarbonImmutable::parse($this->snapshot['occurred_at']);

        return new EventDescription(
            "Удалён контакт с клиентом {$this->client->fullName()} от {$occurredAt->format('d.m H:i')}",
            route('clients.show', $this->client->id),
        );
    }
}
