<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\ClientStatus;
use App\Models\User;

/**
 * A client status was added in the settings.
 */
class ClientStatusCreated extends AbstractDomainEvent
{
    public function __construct(public ClientStatus $clientStatus, ?User $actor)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        return new EventDescription("Новый статус клиента «{$this->clientStatus->name}»", route('settings.client-statuses.index'));
    }
}
