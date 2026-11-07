<?php

namespace App\Events\Communications;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\Client;
use App\Models\Communication;
use App\Models\User;

/**
 * A recorded contact with a client was edited.
 */
class CommunicationUpdated extends AbstractDomainEvent
{
    /**
     * The communication's attributes as they are named in a notice. Attributes without a label
     * (or announced by an event of their own) are not mentioned.
     *
     * @var array<string, string>
     */
    private const LABELS = [
        'channel' => 'способ связи',
        'occurred_at' => 'дата и время',
        'notes' => 'содержание',
    ];

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

    public function describe(): ?EventDescription
    {
        $changed = self::changedLabels($this->changes, self::LABELS);

        if ($changed === null) {
            return null;
        }

        $client = Client::withTrashed()->findOrFail($this->communication->client_id);

        return new EventDescription(
            "Изменён контакт с клиентом {$client->fullName()} от {$this->communication->occurred_at->format('d.m H:i')}: {$changed}",
            route('clients.show', $client->id),
        );
    }
}
