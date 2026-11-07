<?php

namespace App\Events\Clients;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\Client;
use App\Models\User;

/**
 * A client's details were changed.
 */
class ClientUpdated extends AbstractDomainEvent
{
    /**
     * The client's attributes as they are named in a notice. Attributes without a label
     * (or announced by an event of their own) are not mentioned.
     *
     * @var array<string, string>
     */
    private const LABELS = [
        'last_name' => 'фамилия',
        'first_name' => 'имя',
        'middle_name' => 'отчество',
        'parent_id' => 'родитель',
        'phone' => 'телефон',
        'email' => 'email',
        'birth_date' => 'дата рождения',
        'notes' => 'заметки',
    ];

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

    public function describe(): ?EventDescription
    {
        $changed = self::changedLabels($this->changes, self::LABELS);

        if ($changed === null) {
            return null;
        }

        return new EventDescription("Изменены данные клиента {$this->client->fullName()}: {$changed}", route('clients.show', $this->client), []);
    }
}
