<?php

namespace App\Events\Communications;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\Client;
use App\Models\Communication;
use App\Models\User;

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
}
