<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Certification;
use App\Models\User;

/**
 * A certification was added in the settings.
 */
class CertificationCreated extends AbstractDomainEvent
{
    public function __construct(public Certification $certification, ?User $actor)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        return new EventDescription("Новая сертификация «{$this->certification->name}»", route('settings.certifications.index'));
    }
}
