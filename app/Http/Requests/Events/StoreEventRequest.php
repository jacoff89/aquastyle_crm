<?php

namespace App\Http\Requests\Events;

use App\Models\Event;

/**
 * A new event is always planned; it is cancelled or marked done later.
 */
class StoreEventRequest extends EventRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', Event::class);
    }
}
